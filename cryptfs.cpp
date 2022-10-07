/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "Cryptfs"

#include "cryptfs.h"

#include "Checkpoint.h"
#include "CryptoType.h"
#include "EncryptInplace.h"
#include "FsCrypt.h"
#include "Process.h"
#include "ScryptParameters.h"
#include "Utils.h"
#include "VoldUtil.h"
#include "VolumeManager.h"

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <cutils/properties.h>
#include <ext4_utils/ext4_utils.h>
#include <f2fs_sparseblock.h>
#include <fs_mgr.h>
#include <fscrypt/fscrypt.h>
#include <libdm/dm.h>
#include <log/log.h>
#include <logwrap/logwrap.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <selinux/selinux.h>
#include <wakelock/wakelock.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/kdev_t.h>
#include <math.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#ifdef CONFIG_HW_DISK_ENCRYPTION
#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <cryptfs_hw.h>
#endif
extern "C" {
#include <crypto_scrypt.h>
}

using android::base::ParseUint;
using android::base::StringPrintf;
using android::fs_mgr::GetEntryForMountPoint;
using android::vold::CryptoType;
using android::vold::KeyBuffer;
using android::vold::KeyGeneration;
using namespace android::vold;
using namespace android::dm;
using namespace std::chrono_literals;

/* The current cryptfs version */
#define CURRENT_MAJOR_VERSION 1
#define CURRENT_MINOR_VERSION 3

#define CRYPT_FOOTER_TO_PERSIST_OFFSET 0x1000
#define CRYPT_PERSIST_DATA_SIZE 0x1000

#define CRYPT_SECTOR_SIZE 512

#define MAX_CRYPTO_TYPE_NAME_LEN 64

#define MAX_KEY_LEN 48
#define SALT_LEN 16
#define SCRYPT_LEN 32

/* definitions of flags in the structure below */
#define CRYPT_MNT_KEY_UNENCRYPTED 0x1 /* The key for the partition is not encrypted. */
#define CRYPT_ENCRYPTION_IN_PROGRESS 0x2 /* no longer used */
#define CRYPT_INCONSISTENT_STATE                    \
    0x4 /* Set when starting encryption, clear when \
           exit cleanly, either through success or  \
           correctly marked partial encryption */
#define CRYPT_DATA_CORRUPT                      \
    0x8 /* Set when encryption is fine, but the \
           underlying volume is corrupt */
#define CRYPT_FORCE_ENCRYPTION                        \
    0x10 /* Set when it is time to encrypt this       \
            volume on boot. Everything in this        \
            structure is set up correctly as          \
            though device is encrypted except         \
            that the master key is encrypted with the \
            default password. */
#define CRYPT_FORCE_COMPLETE                           \
    0x20 /* Set when the above encryption cycle is     \
            complete. On next cryptkeeper entry, match \
            the password. If it matches fix the master \
            key and remove this flag. */

/* Allowed values for type in the structure below */
#define CRYPT_TYPE_PASSWORD                       \
    0 /* master_key is encrypted with a password  \
       * Must be zero to be compatible with pre-L \
       * devices where type is always password.*/
#define CRYPT_TYPE_DEFAULT                                            \
    1                         /* master_key is encrypted with default \
                               * password */
#define CRYPT_TYPE_PATTERN 2  /* master_key is encrypted with a pattern */
#define CRYPT_TYPE_PIN 3      /* master_key is encrypted with a pin */
#define CRYPT_TYPE_MAX_TYPE 3 /* type cannot be larger than this value */

#define CRYPT_MNT_MAGIC 0xD0B5B1C4
#define PERSIST_DATA_MAGIC 0xE950CD44

/* Key Derivation Function algorithms */
#define KDF_PBKDF2 1
#define KDF_SCRYPT 2
/* Algorithms 3 & 4 deprecated before shipping outside of google, so removed */
#define KDF_SCRYPT_KEYMASTER 5

/* Maximum allowed keymaster blob size. */
#define KEYMASTER_BLOB_SIZE 2048

/* __le32 and __le16 defined in system/extras/ext4_utils/ext4_utils.h */
#define __le8 unsigned char

#if !defined(SHA256_DIGEST_LENGTH)
#define SHA256_DIGEST_LENGTH 32
#endif

/* This structure starts 16,384 bytes before the end of a hardware
 * partition that is encrypted, or in a separate partition.  It's location
 * is specified by a property set in init.<device>.rc.
 * The structure allocates 48 bytes for a key, but the real key size is
 * specified in the struct.  Currently, the code is hardcoded to use 128
 * bit keys.
 * The fields after salt are only valid in rev 1.1 and later stuctures.
 * Obviously, the filesystem does not include the last 16 kbytes
 * of the partition if the crypt_mnt_ftr lives at the end of the
 * partition.
 */

struct crypt_mnt_ftr {
    __le32 magic; /* See above */
    __le16 major_version;
    __le16 minor_version;
    __le32 ftr_size;             /* in bytes, not including key following */
    __le32 flags;                /* See above */
    __le32 keysize;              /* in bytes */
    __le32 crypt_type;           /* how master_key is encrypted. Must be a
                                  * CRYPT_TYPE_XXX value */
    __le64 fs_size;              /* Size of the encrypted fs, in 512 byte sectors */
    __le32 failed_decrypt_count; /* count of # of failed attempts to decrypt and
                                    mount, set to 0 on successful mount */
    unsigned char crypto_type_name[MAX_CRYPTO_TYPE_NAME_LEN]; /* The type of encryption
                                                                 needed to decrypt this
                                                                 partition, null terminated */
    __le32 spare2;                                            /* ignored */
    unsigned char master_key[MAX_KEY_LEN]; /* The encrypted key for decrypting the filesystem */
    unsigned char salt[SALT_LEN];          /* The salt used for this encryption */
    __le64 persist_data_offset[2];         /* Absolute offset to both copies of crypt_persist_data
                                            * on device with that info, either the footer of the
                                            * real_blkdevice or the metadata partition. */

    __le32 persist_data_size; /* The number of bytes allocated to each copy of the
                               * persistent data table*/

    __le8 kdf_type; /* The key derivation function used. */

    /* scrypt parameters. See www.tarsnap.com/scrypt/scrypt.pdf */
    __le8 N_factor;        /* (1 << N) */
    __le8 r_factor;        /* (1 << r) */
    __le8 p_factor;        /* (1 << p) */
    __le64 encrypted_upto; /* no longer used */
    __le8 hash_first_block[SHA256_DIGEST_LENGTH]; /* no longer used */

    /* key_master key, used to sign the derived key which is then used to generate
     * the intermediate key
     * This key should be used for no other purposes! We use this key to sign unpadded
     * data, which is acceptable but only if the key is not reused elsewhere. */
    __le8 keymaster_blob[KEYMASTER_BLOB_SIZE];
    __le32 keymaster_blob_size;

    /* Store scrypt of salted intermediate key. When decryption fails, we can
       check if this matches, and if it does, we know that the problem is with the
       drive, and there is no point in asking the user for more passwords.

       Note that if any part of this structure is corrupt, this will not match and
       we will continue to believe the user entered the wrong password. In that
       case the only solution is for the user to enter a password enough times to
       force a wipe.

       Note also that there is no need to worry about migration. If this data is
       wrong, we simply won't recognise a right password, and will continue to
       prompt. On the first password change, this value will be populated and
       then we will be OK.
     */
    unsigned char scrypted_intermediate_key[SCRYPT_LEN];

    /* sha of this structure with this element set to zero
       Used when encrypting on reboot to validate structure before doing something
       fatal
     */
    unsigned char sha256[SHA256_DIGEST_LENGTH];
};

/* Persistant data that should be available before decryption.
 * Things like airplane mode, locale and timezone are kept
 * here and can be retrieved by the CryptKeeper UI to properly
 * configure the phone before asking for the password
 * This is only valid if the major and minor version above
 * is set to 1.1 or higher.
 *
 * This is a 4K structure.  There are 2 copies, and the code alternates
 * writing one and then clearing the previous one.  The reading
 * code reads the first valid copy it finds, based on the magic number.
 * The absolute offset to the first of the two copies is kept in rev 1.1
 * and higher crypt_mnt_ftr structures.
 */
struct crypt_persist_entry {
    char key[PROPERTY_KEY_MAX];
    char val[PROPERTY_VALUE_MAX];
};

/* Should be exactly 4K in size */
struct crypt_persist_data {
    __le32 persist_magic;
    __le32 persist_valid_entries;
    __le32 persist_spare[30];
    struct crypt_persist_entry persist_entry[0];
};

typedef int (*kdf_func)(const char* passwd, const unsigned char* salt, unsigned char* ikey,
                        void* params);

#define UNUSED __attribute__((unused))

#define HASH_COUNT 2000

constexpr size_t INTERMEDIATE_KEY_LEN_BYTES = 16;
constexpr size_t INTERMEDIATE_IV_LEN_BYTES = 16;
constexpr size_t INTERMEDIATE_BUF_SIZE = (INTERMEDIATE_KEY_LEN_BYTES + INTERMEDIATE_IV_LEN_BYTES);

// SCRYPT_LEN is used by struct crypt_mnt_ftr for its intermediate key.
static_assert(INTERMEDIATE_BUF_SIZE == SCRYPT_LEN, "Mismatch of intermediate key sizes");

#define KEY_IN_FOOTER "footer"

#define DEFAULT_HEX_PASSWORD "64656661756c745f70617373776f7264"
#define DEFAULT_PASSWORD "default_password"

#define CRYPTO_BLOCK_DEVICE "userdata"

#define BREADCRUMB_FILE "/data/misc/vold/convert_fde"

#define EXT4_FS 1
#define F2FS_FS 2

#define TABLE_LOAD_RETRIES 10

#define RSA_KEY_SIZE 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE / 8)
#define RSA_EXPONENT 0x10001
#define KEYMASTER_CRYPTFS_RATE_LIMIT 1  // Maximum one try per second
#define KEY_LEN_BYTES 16

#define RETRY_MOUNT_ATTEMPTS 10
#define RETRY_MOUNT_DELAY_SECONDS 1

#define CREATE_CRYPTO_BLK_DEV_FLAGS_ALLOW_ENCRYPT_OVERRIDE (1)

static unsigned char saved_master_key[MAX_KEY_LEN];
static char* saved_mount_point;
static int master_key_saved = 0;
static struct crypt_persist_data* persist_data = NULL;

static int previous_type;

static char twrp_key_fname[PROPERTY_VALUE_MAX] = "";
static char twrp_real_blkdev[PROPERTY_VALUE_MAX] = "";

#ifdef CONFIG_HW_DISK_ENCRYPTION
static int scrypt_keymaster(const char *passwd, const unsigned char *salt,
                            unsigned char *ikey, void *params);
static void convert_key_to_hex_ascii(const unsigned char *master_key,
                                     unsigned int keysize, char *master_key_ascii);
static int put_crypt_ftr_and_key(struct crypt_mnt_ftr *crypt_ftr);
static int test_mount_hw_encrypted_fs(struct crypt_mnt_ftr* crypt_ftr,
                const char *passwd, const char *mount_point, const char *label);
int cryptfs_changepw_hw_fde(int crypt_type, const char *currentpw,
                                   const char *newpw);
int cryptfs_check_passwd_hw(char *passwd);
int cryptfs_get_master_key(struct crypt_mnt_ftr* ftr, const char* password,
                                   unsigned char* master_key);

static void convert_key_to_hex_ascii_for_upgrade(const unsigned char *master_key,
                                     unsigned int keysize, char *master_key_ascii)
{
    unsigned int i, a;
    unsigned char nibble;

    for (i = 0, a = 0; i < keysize; i++, a += 2) {
        /* For each byte, write out two ascii hex digits */
        nibble = (master_key[i] >> 4) & 0xf;
        master_key_ascii[a] = nibble + (nibble > 9 ? 0x57 : 0x30);

        nibble = master_key[i] & 0xf;
        master_key_ascii[a + 1] = nibble + (nibble > 9 ? 0x57 : 0x30);
    }

    /* Add the null termination */
    master_key_ascii[a] = '\0';
}

static int get_keymaster_hw_fde_passwd(const char* passwd, unsigned char* newpw,
                                  unsigned char* salt,
                                  const struct crypt_mnt_ftr *ftr)
{
    /* if newpw updated, return 0
     * if newpw not updated return -1
     */
    int rc = -1;

    if (should_use_keymaster()) {
        if (scrypt_keymaster(passwd, salt, newpw, (void*)ftr)) {
            SLOGE("scrypt failed");
        } else {
            rc = 0;
        }
    }

    return rc;
}

static int verify_hw_fde_passwd(const char *passwd, struct crypt_mnt_ftr* crypt_ftr)
{
    unsigned char newpw[32] = {0};
    int key_index;
    if (get_keymaster_hw_fde_passwd(passwd, newpw, crypt_ftr->salt, crypt_ftr))
        key_index = set_hw_device_encryption_key(passwd,
                                           (char*) crypt_ftr->crypto_type_name);
    else
        key_index = set_hw_device_encryption_key((const char*)newpw,
                                           (char*) crypt_ftr->crypto_type_name);
    return key_index;
}

static int verify_and_update_hw_fde_passwd(const char *passwd,
                                           struct crypt_mnt_ftr* crypt_ftr)
{
    char* new_passwd = NULL;
    unsigned char newpw[32] = {0};
    int key_index = -1;
    int passwd_updated = -1;
    int ascii_passwd_updated = (crypt_ftr->flags & CRYPT_ASCII_PASSWORD_UPDATED);

    key_index = verify_hw_fde_passwd(passwd, crypt_ftr);
    if (key_index < 0) {
        ++crypt_ftr->failed_decrypt_count;

        if (ascii_passwd_updated) {
            SLOGI("Ascii password was updated");
        } else {
            /* Code in else part would execute only once:
             * When device is upgraded from L->M release.
             * Once upgraded, code flow should never come here.
             * L release passed actual password in hex, so try with hex
             * Each nible of passwd was encoded as a byte, so allocate memory
             * twice of password len plus one more byte for null termination
             */
            if (crypt_ftr->crypt_type == CRYPT_TYPE_DEFAULT) {
                new_passwd = (char*)malloc(strlen(DEFAULT_HEX_PASSWORD) + 1);
                if (new_passwd == NULL) {
                    SLOGE("System out of memory. Password verification  incomplete");
                    goto out;
                }
                strlcpy(new_passwd, DEFAULT_HEX_PASSWORD, strlen(DEFAULT_HEX_PASSWORD) + 1);
            } else {
                new_passwd = (char*)malloc(strlen(passwd) * 2 + 1);
                if (new_passwd == NULL) {
                    SLOGE("System out of memory. Password verification  incomplete");
                    goto out;
                }
                convert_key_to_hex_ascii_for_upgrade((const unsigned char*)passwd,
                                       strlen(passwd), new_passwd);
            }
            key_index = set_hw_device_encryption_key((const char*)new_passwd,
                                       (char*) crypt_ftr->crypto_type_name);
            if (key_index >=0) {
                crypt_ftr->failed_decrypt_count = 0;
                SLOGI("Hex password verified...will try to update with Ascii value");
                /* Before updating password, tie that with keymaster to tie with ROT */

                if (get_keymaster_hw_fde_passwd(passwd, newpw,
                                                crypt_ftr->salt, crypt_ftr)) {
                    passwd_updated = update_hw_device_encryption_key(new_passwd,
                                     passwd, (char*)crypt_ftr->crypto_type_name);
                } else {
                    passwd_updated = update_hw_device_encryption_key(new_passwd,
                                     (const char*)newpw, (char*)crypt_ftr->crypto_type_name);
                }

                if (passwd_updated >= 0) {
                    crypt_ftr->flags |= CRYPT_ASCII_PASSWORD_UPDATED;
                    SLOGI("Ascii password recorded and updated");
                } else {
                    SLOGI("Passwd verified, could not update...Will try next time");
                }
            } else {
                ++crypt_ftr->failed_decrypt_count;
            }
            free(new_passwd);
        }
    } else {
        if (!ascii_passwd_updated)
            crypt_ftr->flags |= CRYPT_ASCII_PASSWORD_UPDATED;
    }
out:
    // update footer before leaving
    put_crypt_ftr_and_key(crypt_ftr);
    return key_index;
}
#endif

constexpr CryptoType aes_128_cbc = CryptoType()
                                           .set_config_name("AES-128-CBC")
                                           .set_kernel_name("aes-cbc-essiv:sha256")
                                           .set_keysize(16);

constexpr CryptoType supported_crypto_types[] = {aes_128_cbc, android::vold::adiantum};

static_assert(validateSupportedCryptoTypes(MAX_KEY_LEN, supported_crypto_types,
                                           array_length(supported_crypto_types)),
              "We have a CryptoType with keysize > MAX_KEY_LEN or which was "
              "incompletely constructed.");

static const CryptoType& get_crypto_type() {
    // We only want to parse this read-only property once.  But we need to wait
    // until the system is initialized before we can read it.  So we use a static
    // scoped within this function to get it only once.
    static CryptoType crypto_type =
            lookup_crypto_algorithm(supported_crypto_types, array_length(supported_crypto_types),
                                    aes_128_cbc, "ro.crypto.fde_algorithm");
    return crypto_type;
}

const KeyGeneration cryptfs_get_keygen() {
    return KeyGeneration{get_crypto_type().get_keysize(), true, false};
}

void set_partition_data(const char* block_device, const char* key_location)
{
  strncpy(twrp_key_fname, key_location, strlen(key_location));
  strncpy(twrp_real_blkdev, block_device, strlen(block_device));
}

/* Store password when userdata is successfully decrypted and mounted.
 * Cleared by cryptfs_clear_password
 *
 * To avoid a double prompt at boot, we need to store the CryptKeeper
 * password and pass it to KeyGuard, which uses it to unlock KeyStore.
 * Since the entire framework is torn down and rebuilt after encryption,
 * we have to use a daemon or similar to store the password. Since vold
 * is secured against IPC except from system processes, it seems a reasonable
 * place to store this.
 *
 * password should be cleared once it has been used.
 *
 * password is aged out after password_max_age_seconds seconds.
 */
static char* password = 0;
static int password_expiry_time = 0;
static const int password_max_age_seconds = 60;

enum class RebootType { reboot, recovery, shutdown };

/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
static void convert_key_to_hex_ascii(const unsigned char* master_key, unsigned int keysize,
                                     char* master_key_ascii) {
    unsigned int i, a;
    unsigned char nibble;

    for (i = 0, a = 0; i < keysize; i++, a += 2) {
        /* For each byte, write out two ascii hex digits */
        nibble = (master_key[i] >> 4) & 0xf;
        master_key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

        nibble = master_key[i] & 0xf;
        master_key_ascii[a + 1] = nibble + (nibble > 9 ? 0x37 : 0x30);
    }

    /* Add the null termination */
    master_key_ascii[a] = '\0';
}

/*
 * If the ro.crypto.fde_sector_size system property is set, append the
 * parameters to make dm-crypt use the specified crypto sector size and round
 * the crypto device size down to a crypto sector boundary.
 */
static int add_sector_size_param(DmTargetCrypt* target, struct crypt_mnt_ftr* ftr) {
    constexpr char DM_CRYPT_SECTOR_SIZE[] = "ro.crypto.fde_sector_size";
    char value[PROPERTY_VALUE_MAX];

    if (property_get(DM_CRYPT_SECTOR_SIZE, value, "") > 0) {
        unsigned int sector_size;

        if (!ParseUint(value, &sector_size) || sector_size < 512 || sector_size > 4096 ||
            (sector_size & (sector_size - 1)) != 0) {
            SLOGE("Invalid value for %s: %s.  Must be >= 512, <= 4096, and a power of 2\n",
                  DM_CRYPT_SECTOR_SIZE, value);
            return -1;
        }

        target->SetSectorSize(sector_size);

        // With this option, IVs will match the sector numbering, instead
        // of being hard-coded to being based on 512-byte sectors.
        target->SetIvLargeSectors();

        // Round the crypto device size down to a crypto sector boundary.
        ftr->fs_size &= ~((sector_size / 512) - 1);
    }
    return 0;
}

#if defined(CONFIG_HW_DISK_ENCRYPTION) && !defined(CONFIG_HW_DISK_ENCRYPT_PERF)
#define DM_CRYPT_BUF_SIZE 4096

static void ioctl_init(struct dm_ioctl* io, size_t dataSize, const char* name, unsigned flags) {
    memset(io, 0, dataSize);
    io->data_size = dataSize;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags;
    if (name) {
        strlcpy(io->name, name, sizeof(io->name));
    }
}

static int load_crypto_mapping_table(struct crypt_mnt_ftr* crypt_ftr,
                                     const unsigned char* master_key, const char* real_blk_name,
                                     const char* name, int fd, const char* extra_params) {
    alignas(struct dm_ioctl) char buffer[DM_CRYPT_BUF_SIZE];
    struct dm_ioctl* io;
    struct dm_target_spec* tgt;
    char* crypt_params;
    // We need two ASCII characters to represent each byte, and need space for
    // the '\0' terminator.
    char master_key_ascii[MAX_KEY_LEN * 2 + 1];
    size_t buff_offset;
    int i;

    io = (struct dm_ioctl*)buffer;

    /* Load the mapping table for this device */
    tgt = (struct dm_target_spec*)&buffer[sizeof(struct dm_ioctl)];

    ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
    io->target_count = 1;
    tgt->status = 0;
    tgt->sector_start = 0;
    tgt->length = crypt_ftr->fs_size;
    crypt_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    buff_offset = crypt_params - buffer;
    SLOGI(
        "Creating crypto dev \"%s\"; cipher=%s, keysize=%u, real_dev=%s, len=%llu, params=\"%s\"\n",
        name, crypt_ftr->crypto_type_name, crypt_ftr->keysize, real_blk_name, tgt->length * 512,
        extra_params);
    if(is_hw_disk_encryption((char*)crypt_ftr->crypto_type_name)) {
        strlcpy(tgt->target_type, "req-crypt",DM_MAX_TYPE_NAME);
        if (is_ice_enabled())
            convert_key_to_hex_ascii(master_key, sizeof(int), master_key_ascii);
        else
            convert_key_to_hex_ascii(master_key, crypt_ftr->keysize, master_key_ascii);
    }
    snprintf(crypt_params, sizeof(buffer) - buff_offset, "%s %s 0 %s 0 %s 0",
             crypt_ftr->crypto_type_name, master_key_ascii,
             real_blk_name, extra_params);

    SLOGI("target_type = %s", tgt->target_type);
    SLOGI("real_blk_name = %s, extra_params = %s", real_blk_name, extra_params);

    crypt_params += strlen(crypt_params) + 1;
    crypt_params =
        (char*)(((unsigned long)crypt_params + 7) & ~8); /* Align to an 8 byte boundary */
    tgt->next = crypt_params - buffer;

    for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
        if (!ioctl(fd, DM_TABLE_LOAD, io)) {
            break;
        }
        usleep(500000);
    }

    if (i == TABLE_LOAD_RETRIES) {
        /* We failed to load the table, return an error */
        return -1;
    } else {
        return i + 1;
    }
}

static int create_crypto_blk_dev_hw(struct crypt_mnt_ftr* crypt_ftr, const unsigned char* master_key,
                                 const char* real_blk_name, std::string* crypto_blk_name,
                                 const char* name, uint32_t flags) {
    char buffer[DM_CRYPT_BUF_SIZE];
    struct dm_ioctl* io;
    unsigned int minor;
    int fd = 0;
    int err;
    int retval = -1;
    int version[3];
    int load_count = 0;
    char encrypted_state[PROPERTY_VALUE_MAX] = {0};
    char progress[PROPERTY_VALUE_MAX] = {0};
    const char *extra_params;

    if ((fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Cannot open device-mapper\n");
        goto errout;
    }

    io = (struct dm_ioctl*)buffer;

    ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
    err = ioctl(fd, DM_DEV_CREATE, io);
    if (err) {
        SLOGE("Cannot create dm-crypt device %s: %s\n", name, strerror(errno));
        goto errout;
    }

    /* Get the device status, in particular, the name of it's device file */
    ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        SLOGE("Cannot retrieve dm-crypt device status\n");
        goto errout;
    }
    minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    snprintf(crypto_blk_name->data(), MAXPATHLEN, "/dev/block/dm-%u", minor);

    if(is_hw_disk_encryption((char*)crypt_ftr->crypto_type_name)) {
      /* Set fde_enabled if either FDE completed or in-progress */
      property_get("ro.crypto.state", encrypted_state, ""); /* FDE completed */
      property_get("vold.encrypt_progress", progress, ""); /* FDE in progress */
      if (!strcmp(encrypted_state, "encrypted") || strcmp(progress, "")) {
        if (is_ice_enabled()) {
          extra_params = "fde_enabled ice allow_encrypt_override";
        } else {
          extra_params = "fde_enabled allow_encrypt_override";
        }
      } else {
          extra_params = "fde_enabled allow_encrypt_override";
      }
      load_count = load_crypto_mapping_table(crypt_ftr, master_key, real_blk_name, name, fd,
                                           extra_params);
    }

    if (load_count < 0) {
        SLOGE("Cannot load dm-crypt mapping table.\n");
        goto errout;
    } else if (load_count > 1) {
        SLOGI("Took %d tries to load dmcrypt table.\n", load_count);
    }

    /* Resume this device to activate it */
    ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);

    if (ioctl(fd, DM_DEV_SUSPEND, io)) {
        SLOGE("Cannot resume the dm-crypt device\n");
        goto errout;
    }

    /* Ensure the dm device has been created before returning. */
    if (android::vold::WaitForFile(crypto_blk_name->c_str(), 1s) < 0) {
        // WaitForFile generates a suitable log message
        goto errout;
    }

    /* We made it here with no errors.  Woot! */
    retval = 0;

errout:
    close(fd); /* If fd is <0 from a failed open call, it's safe to just ignore the close error */

    return retval;
}
#endif

static int create_crypto_blk_dev(struct crypt_mnt_ftr* crypt_ftr, const unsigned char* master_key,
                                 const char* real_blk_name, std::string* crypto_blk_name,
                                 const char* name, uint32_t flags) {
    auto& dm = DeviceMapper::Instance();

    // We need two ASCII characters to represent each byte, and need space for
    // the '\0' terminator.
    char master_key_ascii[MAX_KEY_LEN * 2 + 1];
    convert_key_to_hex_ascii(master_key, crypt_ftr->keysize, master_key_ascii);

    auto target = std::make_unique<DmTargetCrypt>(0, crypt_ftr->fs_size,
                                                  (const char*)crypt_ftr->crypto_type_name,
                                                  master_key_ascii, 0, real_blk_name, 0);
    target->AllowDiscards();

    if (flags & CREATE_CRYPTO_BLK_DEV_FLAGS_ALLOW_ENCRYPT_OVERRIDE) {
        target->AllowEncryptOverride();
    }
    if (add_sector_size_param(target.get(), crypt_ftr)) {
        SLOGE("Error processing dm-crypt sector size param\n");
        return -1;
    }

    DmTable table;
    table.AddTarget(std::move(target));

    int load_count = 1;
    while (load_count < TABLE_LOAD_RETRIES) {
        if (dm.CreateDevice(name, table)) {
            break;
        }
        load_count++;
    }

    if (load_count >= TABLE_LOAD_RETRIES) {
        SLOGE("Cannot load dm-crypt mapping table.\n");
        return -1;
    }
    if (load_count > 1) {
        SLOGI("Took %d tries to load dmcrypt table.\n", load_count);
    }

    if (!dm.GetDmDevicePathByName(name, crypto_blk_name)) {
        SLOGE("Cannot determine dm-crypt path for %s.\n", name);
        return -1;
    }

    /* Ensure the dm device has been created before returning. */
    if (android::vold::WaitForFile(crypto_blk_name->c_str(), 1s) < 0) {
        // WaitForFile generates a suitable log message
        return -1;
    }
    return 0;
}

int delete_crypto_blk_dev(const std::string& name) {
    bool ret;
    auto& dm = DeviceMapper::Instance();
    // TODO(b/149396179) there appears to be a race somewhere in the system where trying
    // to delete the device fails with EBUSY; for now, work around this by retrying.
    int tries = 5;
    while (tries-- > 0) {
        ret = dm.DeleteDevice(name);
        if (ret || errno != EBUSY) {
            break;
        }
        SLOGW("DM_DEV Cannot remove dm-crypt device %s: %s, retrying...\n", name.c_str(),
              strerror(errno));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!ret) {
        SLOGE("DM_DEV Cannot remove dm-crypt device %s: %s\n", name.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

#ifdef CONFIG_HW_DISK_ENCRYPTION
static int test_mount_hw_encrypted_fs(struct crypt_mnt_ftr* crypt_ftr,
             const char *passwd, const char *mount_point, const char *label)
{
    /* Allocate enough space for a 256 bit key, but we may use less */
    unsigned char decrypted_master_key[32];
    std::string crypto_blkdev;
    std::string real_blkdev;
    unsigned int orig_failed_decrypt_count;
    int rc = 0;

    SLOGD("crypt_ftr->fs_size = %lld\n", crypt_ftr->fs_size);
    orig_failed_decrypt_count = crypt_ftr->failed_decrypt_count;

    get_crypt_info(nullptr, &real_blkdev);

    int key_index = 0;
    if(is_hw_disk_encryption((char*)crypt_ftr->crypto_type_name)) {
        key_index = verify_and_update_hw_fde_passwd(passwd, crypt_ftr);
        if (key_index < 0) {
            rc = crypt_ftr->failed_decrypt_count;
            goto errout;
        }
        else {
            if (is_ice_enabled()) {
#ifndef CONFIG_HW_DISK_ENCRYPT_PERF
                if (create_crypto_blk_dev_hw(crypt_ftr, (unsigned char*)&key_index,
                                          real_blkdev.c_str(), &crypto_blkdev, label, 0)) {
                    SLOGE("Error creating decrypted block device");
                    rc = -1;
                    goto errout;
                }
#endif
            } else {
                if (create_crypto_blk_dev_hw(crypt_ftr, decrypted_master_key,
                                          real_blkdev.c_str(), &crypto_blkdev, label, 0)) {
                    SLOGE("Error creating decrypted block device");
                    rc = -1;
                    goto errout;
                }
            }
        }
    }

    if (rc == 0) {
        crypt_ftr->failed_decrypt_count = 0;
        if (orig_failed_decrypt_count != 0) {
            put_crypt_ftr_and_key(crypt_ftr);
        }

        /* Save the name of the crypto block device
         * so we can mount it when restarting the framework. */
#ifdef CONFIG_HW_DISK_ENCRYPT_PERF
        if (!is_ice_enabled())
#endif
        property_set("ro.crypto.fs_crypto_blkdev", crypto_blkdev.c_str());
        master_key_saved = 1;
    }

  errout:
    return rc;
}
#endif

/*
 * Called by vold when it's asked to mount an encrypted external
 * storage volume. The incoming partition has no crypto header/footer,
 * as any metadata is been stored in a separate, small partition.  We
 * assume it must be using our same crypt type and keysize.
 */
int cryptfs_setup_ext_volume(const char* label, const char* real_blkdev, const KeyBuffer& key,
                             std::string* out_crypto_blkdev) {
    auto crypto_type = get_crypto_type();
    if (key.size() != crypto_type.get_keysize()) {
        SLOGE("Raw keysize %zu does not match crypt keysize %zu", key.size(),
              crypto_type.get_keysize());
        return -1;
    }
    uint64_t nr_sec = 0;
    if (android::vold::GetBlockDev512Sectors(real_blkdev, &nr_sec) != android::OK) {
        SLOGE("Failed to get size of %s: %s", real_blkdev, strerror(errno));
        return -1;
    }

    struct crypt_mnt_ftr ext_crypt_ftr;
    memset(&ext_crypt_ftr, 0, sizeof(ext_crypt_ftr));
    ext_crypt_ftr.fs_size = nr_sec;
    ext_crypt_ftr.keysize = crypto_type.get_keysize();
    strlcpy((char*)ext_crypt_ftr.crypto_type_name, crypto_type.get_kernel_name(),
            MAX_CRYPTO_TYPE_NAME_LEN);
    uint32_t flags = 0;
    if (fscrypt_is_native() &&
        android::base::GetBoolProperty("ro.crypto.allow_encrypt_override", false))
        flags |= CREATE_CRYPTO_BLK_DEV_FLAGS_ALLOW_ENCRYPT_OVERRIDE;

    return create_crypto_blk_dev(&ext_crypt_ftr, reinterpret_cast<const unsigned char*>(key.data()),
                                 real_blkdev, out_crypto_blkdev, label, flags);
}

#ifdef CONFIG_HW_DISK_ENCRYPTION
int cryptfs_check_passwd_hw(const char* passwd)
{
    struct crypt_mnt_ftr crypt_ftr;
    int rc;
    unsigned char master_key[KEY_LEN_BYTES];

    /* get key */
    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Error getting crypt footer and key");
        return -1;
    }

    /*
     * in case of manual encryption (from GUI), the encryption is done with
     * default password
     */
    if (crypt_ftr.flags & CRYPT_FORCE_COMPLETE) {
        /* compare scrypted_intermediate_key with stored scrypted_intermediate_key
         * which was created with actual password before reboot.
         */
        rc = cryptfs_get_master_key(&crypt_ftr, passwd, master_key);
        if (rc) {
            SLOGE("password doesn't match");
            rc = ++crypt_ftr.failed_decrypt_count;
            put_crypt_ftr_and_key(&crypt_ftr);
            return rc;
        }

        rc = test_mount_hw_encrypted_fs(&crypt_ftr, DEFAULT_PASSWORD,
            DATA_MNT_POINT, CRYPTO_BLOCK_DEVICE);

        if (rc) {
            SLOGE("Default password did not match on reboot encryption");
            return rc;
        }

        crypt_ftr.flags &= ~CRYPT_FORCE_COMPLETE;
        put_crypt_ftr_and_key(&crypt_ftr);
        rc = cryptfs_changepw(crypt_ftr.crypt_type, DEFAULT_PASSWORD, passwd);
        if (rc) {
            SLOGE("Could not change password on reboot encryption");
            return rc;
        }
    } else
        rc = test_mount_hw_encrypted_fs(&crypt_ftr, passwd,
            DATA_MNT_POINT, CRYPTO_BLOCK_DEVICE);

    if (crypt_ftr.crypt_type != CRYPT_TYPE_DEFAULT) {
        cryptfs_clear_password();
        password = strdup(passwd);
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);
        password_expiry_time = now.tv_sec + password_max_age_seconds;
    }

    return rc;
}
#endif

#define FRAMEWORK_BOOT_WAIT 60

#ifdef CONFIG_HW_DISK_ENCRYPTION
int cryptfs_changepw_hw_fde(int crypt_type, const char *currentpw, const char *newpw)
{
    struct crypt_mnt_ftr crypt_ftr;
    int rc;
    int previous_type;

    /* get key */
    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Error getting crypt footer and key");
        return -1;
    }

    previous_type = crypt_ftr.crypt_type;
    int rc1;
    unsigned char tmp_curpw[32] = {0};
    rc1 = get_keymaster_hw_fde_passwd(crypt_ftr.crypt_type == CRYPT_TYPE_DEFAULT ?
                                      DEFAULT_PASSWORD : currentpw, tmp_curpw,
                                      crypt_ftr.salt, &crypt_ftr);

    crypt_ftr.crypt_type = crypt_type;

    int ret, rc2;
    unsigned char tmp_newpw[32] = {0};

    rc2 = get_keymaster_hw_fde_passwd(crypt_type == CRYPT_TYPE_DEFAULT ?
                                DEFAULT_PASSWORD : newpw , tmp_newpw,
                                crypt_ftr.salt, &crypt_ftr);

    if (is_hw_disk_encryption((char*)crypt_ftr.crypto_type_name)) {
        ret = update_hw_device_encryption_key(
                rc1 ? (previous_type == CRYPT_TYPE_DEFAULT ? DEFAULT_PASSWORD : currentpw) : (const char*)tmp_curpw,
                rc2 ? (crypt_type == CRYPT_TYPE_DEFAULT ? DEFAULT_PASSWORD : newpw): (const char*)tmp_newpw,
                                    (char*)crypt_ftr.crypto_type_name);
        if (ret) {
            SLOGE("Error updating device encryption hardware key ret %d", ret);
            return -1;
        } else {
            SLOGI("Encryption hardware key updated");
        }
    }

    /* save the key */
    put_crypt_ftr_and_key(&crypt_ftr);
    return 0;
}
#endif

/**
 * Test if key is part of the multi-entry (field, index) sequence. Return non-zero if key is in the
 * sequence and its index is greater than or equal to index. Return 0 otherwise.
 */
int match_multi_entry(const char* key, const char* field, unsigned index) {
    std::string key_ = key;
    std::string field_ = field;

    std::string parsed_field;
    unsigned parsed_index;

    std::string::size_type split = key_.find_last_of('_');
    if (split == std::string::npos) {
        parsed_field = key_;
        parsed_index = 0;
    } else {
        parsed_field = key_.substr(0, split);
        parsed_index = std::stoi(key_.substr(split + 1));
    }

    return parsed_field == field_ && parsed_index >= index;
}

const char* cryptfs_get_password() {
    if (fscrypt_is_native()) {
        SLOGE("cryptfs_get_password not valid for file encryption");
        return 0;
    }

    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    if (now.tv_sec < password_expiry_time) {
        return password;
    } else {
        cryptfs_clear_password();
        return 0;
    }
}

void cryptfs_clear_password() {
    if (password) {
        size_t len = strlen(password);
        memset(password, 0, len);
        free(password);
        password = 0;
        password_expiry_time = 0;
    }
}

