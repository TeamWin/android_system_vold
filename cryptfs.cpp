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

//
// This file contains the implementation of the dm-crypt volume metadata
// encryption method, which is deprecated.  Devices that launched with Android
// 11 or higher use a different method instead.  For details, see
// https://source.android.com/security/encryption/metadata#configuration-on-adoptable-storage
//

#define LOG_TAG "Cryptfs"

#include "cryptfs.h"

#include "CryptoType.h"
#include "Utils.h"

#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <cutils/properties.h>
#include <libdm/dm.h>
#include <log/log.h>

#include <chrono>

using android::base::ParseUint;
using android::vold::CryptoType;
using android::vold::KeyBuffer;
using android::vold::KeyGeneration;
using namespace android::dm;
using namespace android::vold;
using namespace std::chrono_literals;

#define MAX_KEY_LEN 48

#define TABLE_LOAD_RETRIES 10

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

/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
static void convert_key_to_hex_ascii(const KeyBuffer& key, char* key_ascii) {
    unsigned int i, a;
    unsigned char nibble;

    for (i = 0, a = 0; i < key.size(); i++, a += 2) {
        /* For each byte, write out two ascii hex digits */
        nibble = (key[i] >> 4) & 0xf;
        key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

        nibble = key[i] & 0xf;
        key_ascii[a + 1] = nibble + (nibble > 9 ? 0x37 : 0x30);
    }

    /* Add the null termination */
    key_ascii[a] = '\0';
}

/*
 * If the ro.crypto.fde_sector_size system property is set, append the
 * parameters to make dm-crypt use the specified crypto sector size and round
 * the crypto device size down to a crypto sector boundary.
 */
static int add_sector_size_param(DmTargetCrypt* target, uint64_t* nr_sec) {
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
        *nr_sec &= ~((sector_size / 512) - 1);
    }
    return 0;
}

<<<<<<< HEAD   (d7dbfc Snap for 8756258 from d96b2ac076f0d82d3c2068cf4dda134bedb11d)
=======
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

static int pbkdf2(const char* passwd, const unsigned char* salt, unsigned char* ikey,
                  void* params UNUSED) {
    SLOGI("Using pbkdf2 for cryptfs KDF");

    /* Turn the password into a key and IV that can decrypt the master key */
    return PKCS5_PBKDF2_HMAC_SHA1(passwd, strlen(passwd), salt, SALT_LEN, HASH_COUNT,
                                  INTERMEDIATE_BUF_SIZE, ikey) != 1;
}

static int scrypt(const char* passwd, const unsigned char* salt, unsigned char* ikey, void* params) {
    SLOGI("Using scrypt for cryptfs KDF");

    struct crypt_mnt_ftr* ftr = (struct crypt_mnt_ftr*)params;

    int N = 1 << ftr->N_factor;
    int r = 1 << ftr->r_factor;
    int p = 1 << ftr->p_factor;

    /* Turn the password into a key and IV that can decrypt the master key */
    crypto_scrypt((const uint8_t*)passwd, strlen(passwd), salt, SALT_LEN, N, r, p, ikey,
                  INTERMEDIATE_BUF_SIZE);

    return 0;
}

static int scrypt_keymaster(const char* passwd, const unsigned char* salt, unsigned char* ikey,
                            void* params) {
    SLOGI("Using scrypt with keymaster for cryptfs KDF");

    int rc;
    size_t signature_size;
    unsigned char* signature;
    struct crypt_mnt_ftr* ftr = (struct crypt_mnt_ftr*)params;

    int N = 1 << ftr->N_factor;
    int r = 1 << ftr->r_factor;
    int p = 1 << ftr->p_factor;

    rc = crypto_scrypt((const uint8_t*)passwd, strlen(passwd), salt, SALT_LEN, N, r, p, ikey,
                       INTERMEDIATE_BUF_SIZE);

    if (rc) {
        SLOGE("scrypt failed");
        return -1;
    }

    if (keymaster_sign_object(ftr, ikey, INTERMEDIATE_BUF_SIZE, &signature, &signature_size)) {
        SLOGE("Signing failed");
        return -1;
    }

    rc = crypto_scrypt(signature, signature_size, salt, SALT_LEN, N, r, p, ikey,
                       INTERMEDIATE_BUF_SIZE);
    free(signature);

    if (rc) {
        SLOGE("scrypt failed");
        return -1;
    }

    return 0;
}

static int encrypt_master_key(const char* passwd, const unsigned char* salt,
                              const unsigned char* decrypted_master_key,
                              unsigned char* encrypted_master_key, struct crypt_mnt_ftr* crypt_ftr,
                              bool create_keymaster_key) {
    unsigned char ikey[INTERMEDIATE_BUF_SIZE] = {0};
    EVP_CIPHER_CTX e_ctx;
    int encrypted_len, final_len;
    int rc = 0;

    /* Turn the password into an intermediate key and IV that can decrypt the master key */
    get_device_scrypt_params(crypt_ftr);

    switch (crypt_ftr->kdf_type) {
        case KDF_SCRYPT_KEYMASTER:
            if (create_keymaster_key && keymaster_create_key(crypt_ftr)) {
                SLOGE("keymaster_create_key failed");
                return -1;
            }

            if (scrypt_keymaster(passwd, salt, ikey, crypt_ftr)) {
                SLOGE("scrypt failed");
                return -1;
            }
            break;

        case KDF_SCRYPT:
            if (scrypt(passwd, salt, ikey, crypt_ftr)) {
                SLOGE("scrypt failed");
                return -1;
            }
            break;

        default:
            SLOGE("Invalid kdf_type");
            return -1;
    }

    /* Initialize the decryption engine */
    EVP_CIPHER_CTX_init(&e_ctx);
    if (!EVP_EncryptInit_ex(&e_ctx, EVP_aes_128_cbc(), NULL, ikey,
                            ikey + INTERMEDIATE_KEY_LEN_BYTES)) {
        SLOGE("EVP_EncryptInit failed\n");
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(&e_ctx, 0); /* Turn off padding as our data is block aligned */

    /* Encrypt the master key */
    if (!EVP_EncryptUpdate(&e_ctx, encrypted_master_key, &encrypted_len, decrypted_master_key,
                           crypt_ftr->keysize)) {
        SLOGE("EVP_EncryptUpdate failed\n");
        return -1;
    }
    if (!EVP_EncryptFinal_ex(&e_ctx, encrypted_master_key + encrypted_len, &final_len)) {
        SLOGE("EVP_EncryptFinal failed\n");
        return -1;
    }

    if (encrypted_len + final_len != static_cast<int>(crypt_ftr->keysize)) {
        SLOGE("EVP_Encryption length check failed with %d, %d bytes\n", encrypted_len, final_len);
        return -1;
    }

    /* Store the scrypt of the intermediate key, so we can validate if it's a
       password error or mount error when things go wrong.
       Note there's no need to check for errors, since if this is incorrect, we
       simply won't wipe userdata, which is the correct default behavior
    */
    int N = 1 << crypt_ftr->N_factor;
    int r = 1 << crypt_ftr->r_factor;
    int p = 1 << crypt_ftr->p_factor;

    rc = crypto_scrypt(ikey, INTERMEDIATE_KEY_LEN_BYTES, crypt_ftr->salt, sizeof(crypt_ftr->salt),
                       N, r, p, crypt_ftr->scrypted_intermediate_key,
                       sizeof(crypt_ftr->scrypted_intermediate_key));

    if (rc) {
        SLOGE("encrypt_master_key: crypto_scrypt failed");
    }

    EVP_CIPHER_CTX_cleanup(&e_ctx);

    return 0;
}

static int decrypt_master_key_aux(const char* passwd, unsigned char* salt,
                                  const unsigned char* encrypted_master_key, size_t keysize,
                                  unsigned char* decrypted_master_key, kdf_func kdf,
                                  void* kdf_params, unsigned char** intermediate_key,
                                  size_t* intermediate_key_size) {
    unsigned char ikey[INTERMEDIATE_BUF_SIZE] = {0};
    EVP_CIPHER_CTX d_ctx;
    int decrypted_len, final_len;

    /* Turn the password into an intermediate key and IV that can decrypt the
       master key */
    if (kdf(passwd, salt, ikey, kdf_params)) {
        SLOGE("kdf failed");
        return -1;
    }

    /* Initialize the decryption engine */
    EVP_CIPHER_CTX_init(&d_ctx);
    if (!EVP_DecryptInit_ex(&d_ctx, EVP_aes_128_cbc(), NULL, ikey,
                            ikey + INTERMEDIATE_KEY_LEN_BYTES)) {
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(&d_ctx, 0); /* Turn off padding as our data is block aligned */
    /* Decrypt the master key */
    if (!EVP_DecryptUpdate(&d_ctx, decrypted_master_key, &decrypted_len, encrypted_master_key,
                           keysize)) {
        return -1;
    }
    if (!EVP_DecryptFinal_ex(&d_ctx, decrypted_master_key + decrypted_len, &final_len)) {
        return -1;
    }

    if (decrypted_len + final_len != static_cast<int>(keysize)) {
        return -1;
    }

    /* Copy intermediate key if needed by params */
    if (intermediate_key && intermediate_key_size) {
        *intermediate_key = (unsigned char*)malloc(INTERMEDIATE_KEY_LEN_BYTES);
        if (*intermediate_key) {
            memcpy(*intermediate_key, ikey, INTERMEDIATE_KEY_LEN_BYTES);
            *intermediate_key_size = INTERMEDIATE_KEY_LEN_BYTES;
        }
    }

    EVP_CIPHER_CTX_cleanup(&d_ctx);

    return 0;
}

static void get_kdf_func(struct crypt_mnt_ftr* ftr, kdf_func* kdf, void** kdf_params) {
    if (ftr->kdf_type == KDF_SCRYPT_KEYMASTER) {
        *kdf = scrypt_keymaster;
        *kdf_params = ftr;
    } else if (ftr->kdf_type == KDF_SCRYPT) {
        *kdf = scrypt;
        *kdf_params = ftr;
    } else {
        *kdf = pbkdf2;
        *kdf_params = NULL;
    }
}

static int decrypt_master_key(const char* passwd, unsigned char* decrypted_master_key,
                              struct crypt_mnt_ftr* crypt_ftr, unsigned char** intermediate_key,
                              size_t* intermediate_key_size) {
    kdf_func kdf;
    void* kdf_params;
    int ret;

    get_kdf_func(crypt_ftr, &kdf, &kdf_params);
    ret = decrypt_master_key_aux(passwd, crypt_ftr->salt, crypt_ftr->master_key, crypt_ftr->keysize,
                                 decrypted_master_key, kdf, kdf_params, intermediate_key,
                                 intermediate_key_size);
    if (ret != 0) {
        SLOGW("failure decrypting master key");
    }

    return ret;
}

static int create_encrypted_random_key(const char* passwd, unsigned char* master_key,
                                       unsigned char* salt, struct crypt_mnt_ftr* crypt_ftr) {
    unsigned char key_buf[MAX_KEY_LEN];

    /* Get some random bits for a key and salt */
    if (android::vold::ReadRandomBytes(sizeof(key_buf), reinterpret_cast<char*>(key_buf)) != 0) {
        return -1;
    }
    if (android::vold::ReadRandomBytes(SALT_LEN, reinterpret_cast<char*>(salt)) != 0) {
        return -1;
    }

    /* Now encrypt it with the password */
    return encrypt_master_key(passwd, salt, key_buf, master_key, crypt_ftr, true);
}

static void ensure_subdirectory_unmounted(const char *prefix) {
    std::vector<std::string> umount_points;
    std::unique_ptr<FILE, int (*)(FILE*)> mnts(setmntent("/proc/mounts", "r"), endmntent);
    if (!mnts) {
        SLOGW("could not read mount files");
        return;
    }

    //Find sudirectory mount point
    mntent* mentry;
    std::string top_directory(prefix);
    if (!android::base::EndsWith(prefix, "/")) {
        top_directory = top_directory + "/";
    }
    while ((mentry = getmntent(mnts.get())) != nullptr) {
        if (strcmp(mentry->mnt_dir, top_directory.c_str()) == 0) {
            continue;
        }

        if (android::base::StartsWith(mentry->mnt_dir, top_directory)) {
            SLOGW("found sub-directory mount %s - %s\n", prefix, mentry->mnt_dir);
            umount_points.push_back(mentry->mnt_dir);
        }
    }

    //Sort by path length to umount longest path first
    std::sort(std::begin(umount_points), std::end(umount_points),
        [](const std::string& s1, const std::string& s2) {return s1.length() > s2.length(); });

    for (std::string& mount_point : umount_points) {
        umount(mount_point.c_str());
        SLOGW("umount sub-directory mount %s\n", mount_point.c_str());
    }
}

static int wait_and_unmount(const char* mountpoint) {
    int i, err, rc;

    // Subdirectory mount will cause a failure of umount.
    ensure_subdirectory_unmounted(mountpoint);
#define WAIT_UNMOUNT_COUNT 200

    /*  Now umount the tmpfs filesystem */
    for (i = 0; i < WAIT_UNMOUNT_COUNT; i++) {
        if (umount(mountpoint) == 0) {
            break;
        }

        if (errno == EINVAL) {
            /* EINVAL is returned if the directory is not a mountpoint,
             * i.e. there is no filesystem mounted there.  So just get out.
             */
            break;
        }

        err = errno;

        // If it's taking too long, kill the processes with open files.
        //
        // Originally this logic was only a fail-safe, but now it's relied on to
        // kill certain processes that aren't stopped by init because they
        // aren't in the main or late_start classes.  So to avoid waiting for
        // too long, we now are fairly aggressive in starting to kill processes.
        static_assert(WAIT_UNMOUNT_COUNT >= 4);
        if (i == 2) {
            SLOGW("sending SIGTERM to processes with open files\n");
            android::vold::KillProcessesWithOpenFiles(mountpoint, SIGTERM);
        } else if (i >= 3) {
            SLOGW("sending SIGKILL to processes with open files\n");
            android::vold::KillProcessesWithOpenFiles(mountpoint, SIGKILL);
        }

        usleep(100000);
    }

    if (i < WAIT_UNMOUNT_COUNT) {
        SLOGD("unmounting %s succeeded\n", mountpoint);
        rc = 0;
    } else {
        android::vold::KillProcessesWithOpenFiles(mountpoint, 0);
        SLOGE("unmounting %s failed: %s\n", mountpoint, strerror(err));
        rc = -1;
    }

    return rc;
}

static void prep_data_fs(void) {
    // NOTE: post_fs_data results in init calling back around to vold, so all
    // callers to this method must be async

    /* Do the prep of the /data filesystem */
    property_set("vold.post_fs_data_done", "0");
    property_set("vold.decrypt", "trigger_post_fs_data");
    SLOGD("Just triggered post_fs_data");

    /* Wait a max of 50 seconds, hopefully it takes much less */
    while (!android::base::WaitForProperty("vold.post_fs_data_done", "1", std::chrono::seconds(15))) {
        /* We timed out to prep /data in time.  Continue wait. */
        SLOGE("waited 15s for vold.post_fs_data_done, still waiting...");
    }
    SLOGD("post_fs_data done");
}

static void cryptfs_set_corrupt() {
    // Mark the footer as bad
    struct crypt_mnt_ftr crypt_ftr;
    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Failed to get crypto footer - panic");
        return;
    }

    crypt_ftr.flags |= CRYPT_DATA_CORRUPT;
    if (put_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Failed to set crypto footer - panic");
        return;
    }
}

static void cryptfs_trigger_restart_min_framework() {
    if (fs_mgr_do_tmpfs_mount(DATA_MNT_POINT)) {
        SLOGE("Failed to mount tmpfs on data - panic");
        return;
    }

    if (property_set("vold.decrypt", "trigger_post_fs_data")) {
        SLOGE("Failed to trigger post fs data - panic");
        return;
    }

    if (property_set("vold.decrypt", "trigger_restart_min_framework")) {
        SLOGE("Failed to trigger restart min framework - panic");
        return;
    }
}

/* returns < 0 on failure */
static int cryptfs_restart_internal(int restart_main) {
    std::string crypto_blkdev;
#ifdef CONFIG_HW_DISK_ENCRYPTION
    std::string blkdev;
#endif
    int rc = -1;
    static int restart_successful = 0;

    /* Validate that it's OK to call this routine */
    if (!master_key_saved) {
        SLOGE("Encrypted filesystem not validated, aborting");
        return -1;
    }

    if (restart_successful) {
        SLOGE("System already restarted with encrypted disk, aborting");
        return -1;
    }

    if (restart_main) {
        /* Here is where we shut down the framework.  The init scripts
         * start all services in one of these classes: core, early_hal, hal,
         * main and late_start. To get to the minimal UI for PIN entry, we
         * need to start core, early_hal, hal and main. When we want to
         * shutdown the framework again, we need to stop most of the services in
         * these classes, but only those services that were started after
         * /data was mounted. This excludes critical services like vold and
         * ueventd, which need to keep running. We could possible stop
         * even fewer services, but because we want services to pick up APEX
         * libraries from the real /data, restarting is better, as it makes
         * these devices consistent with FBE devices and lets them use the
         * most recent code.
         *
         * Once these services have stopped, we should be able
         * to umount the tmpfs /data, then mount the encrypted /data.
         * We then restart the class core, hal, main, and also the class
         * late_start.
         *
         * At the moment, I've only put a few things in late_start that I know
         * are not needed to bring up the framework, and that also cause problems
         * with unmounting the tmpfs /data, but I hope to add add more services
         * to the late_start class as we optimize this to decrease the delay
         * till the user is asked for the password to the filesystem.
         */

        /* The init files are setup to stop the right set of services when
         * vold.decrypt is set to trigger_shutdown_framework.
         */
        property_set("vold.decrypt", "trigger_shutdown_framework");
        SLOGD("Just asked init to shut down class main\n");

        /* Ugh, shutting down the framework is not synchronous, so until it
         * can be fixed, this horrible hack will wait a moment for it all to
         * shut down before proceeding.  Without it, some devices cannot
         * restart the graphics services.
         */
        sleep(2);
    }

    /* Now that the framework is shutdown, we should be able to umount()
     * the tmpfs filesystem, and mount the real one.
     */

#if defined(CONFIG_HW_DISK_ENCRYPTION)
#if defined(CONFIG_HW_DISK_ENCRYPT_PERF)
    if (is_ice_enabled()) {
        get_crypt_info(nullptr, &blkdev);
        if (set_ice_param(START_ENCDEC)) {
             SLOGE("Failed to set ICE data");
             return -1;
        }
    }
#else
    blkdev = android::base::GetProperty("ro.crypto.fs_crypto_blkdev", "");
    if (blkdev.empty()) {
         SLOGE("fs_crypto_blkdev not set\n");
         return -1;
    }
    if (!(rc = wait_and_unmount(DATA_MNT_POINT))) {
#endif
#else
    crypto_blkdev = android::base::GetProperty("ro.crypto.fs_crypto_blkdev", "");
    if (crypto_blkdev.empty()) {
        SLOGE("fs_crypto_blkdev not set\n");
        return -1;
    }

    if (!(rc = wait_and_unmount(DATA_MNT_POINT))) {
#endif
        /* If ro.crypto.readonly is set to 1, mount the decrypted
         * filesystem readonly.  This is used when /data is mounted by
         * recovery mode.
         */
        char ro_prop[PROPERTY_VALUE_MAX];
        property_get("ro.crypto.readonly", ro_prop, "");
        if (strlen(ro_prop) > 0 && std::stoi(ro_prop)) {
            auto entry = GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
            if (entry != nullptr) {
                entry->flags |= MS_RDONLY;
            }
        }

        /* If that succeeded, then mount the decrypted filesystem */
        int retries = RETRY_MOUNT_ATTEMPTS;
        int mount_rc;

        /*
         * fs_mgr_do_mount runs fsck. Use setexeccon to run trusted
         * partitions in the fsck domain.
         */
        if (setexeccon(android::vold::sFsckContext)) {
            SLOGE("Failed to setexeccon");
            return -1;
        }
        bool needs_cp = android::vold::cp_needsCheckpoint();
#ifdef CONFIG_HW_DISK_ENCRYPTION
        while ((mount_rc = fs_mgr_do_mount(&fstab_default, DATA_MNT_POINT, blkdev.data(), 0,
                                           needs_cp, false)) != 0) {
#else
        while ((mount_rc = fs_mgr_do_mount(&fstab_default, DATA_MNT_POINT, crypto_blkdev.data(), 0,
                                           needs_cp, false)) != 0) {
#endif
            if (mount_rc == FS_MGR_DOMNT_BUSY) {
                /* TODO: invoke something similar to
                   Process::killProcessWithOpenFiles(DATA_MNT_POINT,
                                   retries > RETRY_MOUNT_ATTEMPT/2 ? 1 : 2 ) */
#ifdef CONFIG_HW_DISK_ENCRYPTION
                SLOGI("Failed to mount %s because it is busy - waiting", blkdev.c_str());
#else
                SLOGI("Failed to mount %s because it is busy - waiting", crypto_blkdev.c_str());
#endif
                if (--retries) {
                    sleep(RETRY_MOUNT_DELAY_SECONDS);
                } else {
                    /* Let's hope that a reboot clears away whatever is keeping
                       the mount busy */
                    cryptfs_reboot(RebootType::reboot);
                }
            } else {
#ifdef CONFIG_HW_DISK_ENCRYPTION
                if (--retries) {
                    sleep(RETRY_MOUNT_DELAY_SECONDS);
                } else {
                    SLOGE("Failed to mount decrypted data");
                    cryptfs_set_corrupt();
                    cryptfs_trigger_restart_min_framework();
                    SLOGI("Started framework to offer wipe");
                    return -1;
                }
#else
                SLOGE("Failed to mount decrypted data");
                cryptfs_set_corrupt();
                cryptfs_trigger_restart_min_framework();
                SLOGI("Started framework to offer wipe");
                if (setexeccon(NULL)) {
                    SLOGE("Failed to setexeccon");
                }
                return -1;
#endif
            }
        }
        if (setexeccon(NULL)) {
            SLOGE("Failed to setexeccon");
            return -1;
        }

        /* Create necessary paths on /data */
        prep_data_fs();
        property_set("vold.decrypt", "trigger_load_persist_props");

        /* startup service classes main and late_start */
        property_set("vold.decrypt", "trigger_restart_framework");
        SLOGD("Just triggered restart_framework\n");

        /* Give it a few moments to get started */
        sleep(1);
#ifndef CONFIG_HW_DISK_ENCRYPT_PERF
    }
#endif

    if (rc == 0) {
        restart_successful = 1;
    }

    return rc;
}

int cryptfs_restart(void) {
    SLOGI("cryptfs_restart");
    if (fscrypt_is_native()) {
        SLOGE("cryptfs_restart not valid for file encryption:");
        return -1;
    }

    /* Call internal implementation forcing a restart of main service group */
    return cryptfs_restart_internal(1);
}

static int do_crypto_complete(const char* mount_point) {
    struct crypt_mnt_ftr crypt_ftr;
    char encrypted_state[PROPERTY_VALUE_MAX];

    property_get("ro.crypto.state", encrypted_state, "");
    if (strcmp(encrypted_state, "encrypted")) {
        SLOGE("not running with encryption, aborting");
        return CRYPTO_COMPLETE_NOT_ENCRYPTED;
    }

    // crypto_complete is full disk encrypted status
    if (fscrypt_is_native()) {
        return CRYPTO_COMPLETE_NOT_ENCRYPTED;
    }

    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        std::string key_loc;
        get_crypt_info(&key_loc, nullptr);

        /*
         * Only report this error if key_loc is a file and it exists.
         * If the device was never encrypted, and /data is not mountable for
         * some reason, returning 1 should prevent the UI from presenting the
         * a "enter password" screen, or worse, a "press button to wipe the
         * device" screen.
         */
        if (!key_loc.empty() && key_loc[0] == '/' && (access("key_loc", F_OK) == -1)) {
            SLOGE("master key file does not exist, aborting");
            return CRYPTO_COMPLETE_NOT_ENCRYPTED;
        } else {
            SLOGE("Error getting crypt footer and key\n");
            return CRYPTO_COMPLETE_BAD_METADATA;
        }
    }

    // Test for possible error flags
    if (crypt_ftr.flags & CRYPT_ENCRYPTION_IN_PROGRESS) {
        SLOGE("Encryption process is partway completed\n");
        return CRYPTO_COMPLETE_PARTIAL;
    }

    if (crypt_ftr.flags & CRYPT_INCONSISTENT_STATE) {
        SLOGE("Encryption process was interrupted but cannot continue\n");
        return CRYPTO_COMPLETE_INCONSISTENT;
    }

    if (crypt_ftr.flags & CRYPT_DATA_CORRUPT) {
        SLOGE("Encryption is successful but data is corrupt\n");
        return CRYPTO_COMPLETE_CORRUPT;
    }

    /* We passed the test! We shall diminish, and return to the west */
    return CRYPTO_COMPLETE_ENCRYPTED;
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

static int test_mount_encrypted_fs(struct crypt_mnt_ftr* crypt_ftr, const char* passwd,
                                   const char* mount_point, const char* label) {
    unsigned char decrypted_master_key[MAX_KEY_LEN];
    std::string crypto_blkdev;
    std::string real_blkdev;
    char tmp_mount_point[64];
    unsigned int orig_failed_decrypt_count;
    int rc;
    int upgrade = 0;
    unsigned char* intermediate_key = 0;
    size_t intermediate_key_size = 0;
    int N = 1 << crypt_ftr->N_factor;
    int r = 1 << crypt_ftr->r_factor;
    int p = 1 << crypt_ftr->p_factor;

    SLOGD("crypt_ftr->fs_size = %lld\n", crypt_ftr->fs_size);
    orig_failed_decrypt_count = crypt_ftr->failed_decrypt_count;

    if (!(crypt_ftr->flags & CRYPT_MNT_KEY_UNENCRYPTED)) {
        if (decrypt_master_key(passwd, decrypted_master_key, crypt_ftr, &intermediate_key,
                               &intermediate_key_size)) {
            SLOGE("Failed to decrypt master key\n");
            rc = -1;
            goto errout;
        }
    }

    get_crypt_info(nullptr, &real_blkdev);

    // Create crypto block device - all (non fatal) code paths
    // need it
    if (create_crypto_blk_dev(crypt_ftr, decrypted_master_key, real_blkdev.c_str(), &crypto_blkdev,
                              label, 0)) {
        SLOGE("Error creating decrypted block device\n");
        rc = -1;
        goto errout;
    }

    /* Work out if the problem is the password or the data */
    unsigned char scrypted_intermediate_key[sizeof(crypt_ftr->scrypted_intermediate_key)];

    rc = crypto_scrypt(intermediate_key, intermediate_key_size, crypt_ftr->salt,
                       sizeof(crypt_ftr->salt), N, r, p, scrypted_intermediate_key,
                       sizeof(scrypted_intermediate_key));

    // Does the key match the crypto footer?
    if (rc == 0 && memcmp(scrypted_intermediate_key, crypt_ftr->scrypted_intermediate_key,
                          sizeof(scrypted_intermediate_key)) == 0) {
        SLOGI("Password matches");
        rc = 0;
    } else {
        /* Try mounting the file system anyway, just in case the problem's with
         * the footer, not the key. */
        snprintf(tmp_mount_point, sizeof(tmp_mount_point), "%s/tmp_mnt", mount_point);
        mkdir(tmp_mount_point, 0755);
        if (fs_mgr_do_mount(&fstab_default, DATA_MNT_POINT,
                            const_cast<char*>(crypto_blkdev.c_str()), tmp_mount_point)) {
            SLOGE("Error temp mounting decrypted block device\n");
            delete_crypto_blk_dev(label);

            rc = ++crypt_ftr->failed_decrypt_count;
            put_crypt_ftr_and_key(crypt_ftr);
        } else {
            /* Success! */
            SLOGI("Password did not match but decrypted drive mounted - continue");
            umount(tmp_mount_point);
            rc = 0;
        }
    }

    if (rc == 0) {
        crypt_ftr->failed_decrypt_count = 0;
        if (orig_failed_decrypt_count != 0) {
            put_crypt_ftr_and_key(crypt_ftr);
        }

        /* Save the name of the crypto block device
         * so we can mount it when restarting the framework. */
        property_set("ro.crypto.fs_crypto_blkdev", crypto_blkdev.c_str());

        /* Also save a the master key so we can reencrypted the key
         * the key when we want to change the password on it. */
        memcpy(saved_master_key, decrypted_master_key, crypt_ftr->keysize);
        saved_mount_point = strdup(mount_point);
        master_key_saved = 1;
        SLOGD("%s(): Master key saved\n", __FUNCTION__);
        rc = 0;

        // Upgrade if we're not using the latest KDF.
        if (crypt_ftr->kdf_type != KDF_SCRYPT_KEYMASTER) {
            crypt_ftr->kdf_type = KDF_SCRYPT_KEYMASTER;
            upgrade = 1;
        }

        if (upgrade) {
            rc = encrypt_master_key(passwd, crypt_ftr->salt, saved_master_key,
                                    crypt_ftr->master_key, crypt_ftr, true);
            if (!rc) {
                rc = put_crypt_ftr_and_key(crypt_ftr);
            }
            SLOGD("Key Derivation Function upgrade: rc=%d\n", rc);

            // Do not fail even if upgrade failed - machine is bootable
            // Note that if this code is ever hit, there is a *serious* problem
            // since KDFs should never fail. You *must* fix the kdf before
            // proceeding!
            if (rc) {
                SLOGW(
                    "Upgrade failed with error %d,"
                    " but continuing with previous state",
                    rc);
                rc = 0;
            }
        }
    }

errout:
    if (intermediate_key) {
        memset(intermediate_key, 0, intermediate_key_size);
        free(intermediate_key);
    }
    return rc;
}

>>>>>>> CHANGE (c0dab3 fscrypt: move functionality to libvold)
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

    auto& dm = DeviceMapper::Instance();

    // We need two ASCII characters to represent each byte, and need space for
    // the '\0' terminator.
    char key_ascii[MAX_KEY_LEN * 2 + 1];
    convert_key_to_hex_ascii(key, key_ascii);

    auto target = std::make_unique<DmTargetCrypt>(0, nr_sec, crypto_type.get_kernel_name(),
                                                  key_ascii, 0, real_blkdev, 0);
    target->AllowDiscards();

    if (fscrypt_is_native() &&
        android::base::GetBoolProperty("ro.crypto.allow_encrypt_override", false)) {
        target->AllowEncryptOverride();
    }
    if (add_sector_size_param(target.get(), &nr_sec)) {
        SLOGE("Error processing dm-crypt sector size param\n");
        return -1;
    }

    DmTable table;
    table.AddTarget(std::move(target));

    int load_count = 1;
    while (load_count < TABLE_LOAD_RETRIES) {
        if (dm.CreateDevice(label, table)) {
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

    if (!dm.GetDmDevicePathByName(label, out_crypto_blkdev)) {
        SLOGE("Cannot determine dm-crypt path for %s.\n", label);
        return -1;
    }

    /* Ensure the dm device has been created before returning. */
    if (android::vold::WaitForFile(out_crypto_blkdev->c_str(), 1s) < 0) {
        // WaitForFile generates a suitable log message
        return -1;
    }
    return 0;
}
