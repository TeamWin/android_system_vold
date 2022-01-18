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
    if (fname[0] != '/') {
        SLOGE("Unexpected value for crypto key location\n");
        return -1;
    }
    if ((fd = open(fname, O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Cannot open footer file %s for get\n", fname);
        return -1;
    }

    /* Make sure it's 16 Kbytes in length */
    fstat(fd, &statbuf);
    if (S_ISREG(statbuf.st_mode) && (statbuf.st_size != 0x4000)) {
        SLOGE("footer file %s is not the expected size!\n", fname);
        goto errout;
    }

    /* Seek to the start of the crypt footer */
    if (lseek64(fd, starting_off, SEEK_SET) == -1) {
        SLOGE("Cannot seek to real block device footer\n");
        goto errout;
    }

    if ((cnt = read(fd, crypt_ftr, sizeof(struct crypt_mnt_ftr))) != sizeof(struct crypt_mnt_ftr)) {
        SLOGE("Cannot read real block device footer\n");
        goto errout;
    }

    if (crypt_ftr->magic != CRYPT_MNT_MAGIC) {
        SLOGE("Bad magic for real block device %s\n", fname);
        goto errout;
    }

    if (crypt_ftr->major_version != CURRENT_MAJOR_VERSION) {
        SLOGE("Cannot understand major version %d real block device footer; expected %d\n",
              crypt_ftr->major_version, CURRENT_MAJOR_VERSION);
        goto errout;
    }

    // We risk buffer overflows with oversized keys, so we just reject them.
    // 0-sized keys are problematic (essentially by-passing encryption), and
    // AES-CBC key wrapping only works for multiples of 16 bytes.
    if ((crypt_ftr->keysize == 0) || ((crypt_ftr->keysize % 16) != 0) ||
        (crypt_ftr->keysize > MAX_KEY_LEN)) {
        SLOGE(
            "Invalid keysize (%u) for block device %s; Must be non-zero, "
            "divisible by 16, and <= %d\n",
            crypt_ftr->keysize, fname, MAX_KEY_LEN);
        goto errout;
    }

    if (crypt_ftr->minor_version > CURRENT_MINOR_VERSION) {
        SLOGW("Warning: crypto footer minor version %d, expected <= %d, continuing...\n",
              crypt_ftr->minor_version, CURRENT_MINOR_VERSION);
    }

    /* If this is a verion 1.0 crypt_ftr, make it a 1.1 crypt footer, and update the
     * copy on disk before returning.
     */
    if (crypt_ftr->minor_version < CURRENT_MINOR_VERSION) {
        upgrade_crypt_ftr(fd, crypt_ftr, starting_off);
    }

    /* Success! */
    rc = 0;

errout:
    close(fd);
    return rc;
}

static int validate_persistent_data_storage(struct crypt_mnt_ftr* crypt_ftr) {
    if (crypt_ftr->persist_data_offset[0] + crypt_ftr->persist_data_size >
        crypt_ftr->persist_data_offset[1]) {
        SLOGE("Crypt_ftr persist data regions overlap");
        return -1;
    }

    if (crypt_ftr->persist_data_offset[0] >= crypt_ftr->persist_data_offset[1]) {
        SLOGE("Crypt_ftr persist data region 0 starts after region 1");
        return -1;
    }

    if (((crypt_ftr->persist_data_offset[1] + crypt_ftr->persist_data_size) -
         (crypt_ftr->persist_data_offset[0] - CRYPT_FOOTER_TO_PERSIST_OFFSET)) >
        CRYPT_FOOTER_OFFSET) {
        SLOGE("Persistent data extends past crypto footer");
        return -1;
    }

    return 0;
}

static int load_persistent_data(void) {
    struct crypt_mnt_ftr crypt_ftr;
    struct crypt_persist_data* pdata = NULL;
    char encrypted_state[PROPERTY_VALUE_MAX];
    char* fname;
    int found = 0;
    int fd;
    int ret;
    int i;

    if (persist_data) {
        /* Nothing to do, we've already loaded or initialized it */
        return 0;
    }

    /* If not encrypted, just allocate an empty table and initialize it */
    property_get("ro.crypto.state", encrypted_state, "");
    if (strcmp(encrypted_state, "encrypted")) {
        pdata = (crypt_persist_data*)malloc(CRYPT_PERSIST_DATA_SIZE);
        if (pdata) {
            init_empty_persist_data(pdata, CRYPT_PERSIST_DATA_SIZE);
            persist_data = pdata;
            return 0;
        }
        return -1;
    }

    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        return -1;
    }

    if ((crypt_ftr.major_version < 1) ||
        (crypt_ftr.major_version == 1 && crypt_ftr.minor_version < 1)) {
        SLOGE("Crypt_ftr version doesn't support persistent data");
        return -1;
    }

    if (get_crypt_ftr_info(&fname, NULL)) {
        return -1;
    }

    ret = validate_persistent_data_storage(&crypt_ftr);
    if (ret) {
        return -1;
    }

    fd = open(fname, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        SLOGE("Cannot open %s metadata file", fname);
        return -1;
    }

    pdata = (crypt_persist_data*)malloc(crypt_ftr.persist_data_size);
    if (pdata == NULL) {
        SLOGE("Cannot allocate memory for persistent data");
        goto err;
    }

    for (i = 0; i < 2; i++) {
        if (lseek64(fd, crypt_ftr.persist_data_offset[i], SEEK_SET) < 0) {
            SLOGE("Cannot seek to read persistent data on %s", fname);
            goto err2;
        }
        if (unix_read(fd, pdata, crypt_ftr.persist_data_size) < 0) {
            SLOGE("Error reading persistent data on iteration %d", i);
            goto err2;
        }
        if (pdata->persist_magic == PERSIST_DATA_MAGIC) {
            found = 1;
            break;
        }
    }

    if (!found) {
        SLOGI("Could not find valid persistent data, creating");
        init_empty_persist_data(pdata, crypt_ftr.persist_data_size);
    }

    /* Success */
    persist_data = pdata;
    close(fd);
    return 0;

err2:
    free(pdata);

err:
    close(fd);
    return -1;
}

static int save_persistent_data(void) {
    struct crypt_mnt_ftr crypt_ftr;
    struct crypt_persist_data* pdata;
    char* fname;
    off64_t write_offset;
    off64_t erase_offset;
    int fd;
    int ret;

    if (persist_data == NULL) {
        SLOGE("No persistent data to save");
        return -1;
    }

    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        return -1;
    }

    if ((crypt_ftr.major_version < 1) ||
        (crypt_ftr.major_version == 1 && crypt_ftr.minor_version < 1)) {
        SLOGE("Crypt_ftr version doesn't support persistent data");
        return -1;
    }

    ret = validate_persistent_data_storage(&crypt_ftr);
    if (ret) {
        return -1;
    }

    if (get_crypt_ftr_info(&fname, NULL)) {
        return -1;
    }

    fd = open(fname, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        SLOGE("Cannot open %s metadata file", fname);
        return -1;
    }

    pdata = (crypt_persist_data*)malloc(crypt_ftr.persist_data_size);
    if (pdata == NULL) {
        SLOGE("Cannot allocate persistant data");
        goto err;
    }

    if (lseek64(fd, crypt_ftr.persist_data_offset[0], SEEK_SET) < 0) {
        SLOGE("Cannot seek to read persistent data on %s", fname);
        goto err2;
    }

    if (unix_read(fd, pdata, crypt_ftr.persist_data_size) < 0) {
        SLOGE("Error reading persistent data before save");
        goto err2;
    }

    if (pdata->persist_magic == PERSIST_DATA_MAGIC) {
        /* The first copy is the curent valid copy, so write to
         * the second copy and erase this one */
        write_offset = crypt_ftr.persist_data_offset[1];
        erase_offset = crypt_ftr.persist_data_offset[0];
    } else {
        /* The second copy must be the valid copy, so write to
         * the first copy, and erase the second */
        write_offset = crypt_ftr.persist_data_offset[0];
        erase_offset = crypt_ftr.persist_data_offset[1];
    }

    /* Write the new copy first, if successful, then erase the old copy */
    if (lseek64(fd, write_offset, SEEK_SET) < 0) {
        SLOGE("Cannot seek to write persistent data");
        goto err2;
    }
    if (unix_write(fd, persist_data, crypt_ftr.persist_data_size) ==
        (int)crypt_ftr.persist_data_size) {
        if (lseek64(fd, erase_offset, SEEK_SET) < 0) {
            SLOGE("Cannot seek to erase previous persistent data");
            goto err2;
        }
        fsync(fd);
        memset(pdata, 0, crypt_ftr.persist_data_size);
        if (unix_write(fd, pdata, crypt_ftr.persist_data_size) != (int)crypt_ftr.persist_data_size) {
            SLOGE("Cannot write to erase previous persistent data");
            goto err2;
        }
        fsync(fd);
    } else {
        SLOGE("Cannot write to save persistent data");
        goto err2;
    }

    /* Success */
    free(pdata);
    close(fd);
    return 0;

err2:
    free(pdata);
err:
    close(fd);
    return -1;
}

int cryptfs_check_footer()
{
    int rc = -1;
    struct crypt_mnt_ftr crypt_ftr;

    rc = get_crypt_ftr_and_key(&crypt_ftr);

    return rc;
}

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

int cryptfs_crypto_complete(void) {
    return do_crypto_complete("/data");
}

int check_unmounted_and_get_ftr(struct crypt_mnt_ftr* crypt_ftr) {
    char encrypted_state[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.state", encrypted_state, "");
    if (master_key_saved || strcmp(encrypted_state, "encrypted")) {
        SLOGE(
            "encrypted fs already validated or not running with encryption,"
            " aborting");
        return -1;
    }

    if (get_crypt_ftr_and_key(crypt_ftr)) {
        SLOGE("Error getting crypt footer and key");
        return -1;
    }

    return 0;
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

int cryptfs_check_passwd(const char* passwd) {
    SLOGI("cryptfs_check_passwd");
    if (fscrypt_is_native()) {
        SLOGE("cryptfs_check_passwd not valid for file encryption");
        return -1;
    }

    struct crypt_mnt_ftr crypt_ftr;
    int rc;

    rc = check_unmounted_and_get_ftr(&crypt_ftr);
    if (rc) {
        SLOGE("Could not get footer");
        return rc;
    }

#ifdef CONFIG_HW_DISK_ENCRYPTION
    if (is_hw_disk_encryption((char*)crypt_ftr.crypto_type_name))
        return cryptfs_check_passwd_hw(passwd);
#endif

    rc = test_mount_encrypted_fs(&crypt_ftr, passwd, DATA_MNT_POINT, CRYPTO_BLOCK_DEVICE);
    if (rc) {
        SLOGE("Password did not match");
        return rc;
    }

    if (crypt_ftr.flags & CRYPT_FORCE_COMPLETE) {
        // Here we have a default actual password but a real password
        // we must test against the scrypted value
        // First, we must delete the crypto block device that
        // test_mount_encrypted_fs leaves behind as a side effect
        delete_crypto_blk_dev(CRYPTO_BLOCK_DEVICE);
        rc = test_mount_encrypted_fs(&crypt_ftr, DEFAULT_PASSWORD, DATA_MNT_POINT,
                                     CRYPTO_BLOCK_DEVICE);
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
    }

    if (crypt_ftr.crypt_type != CRYPT_TYPE_DEFAULT) {
        cryptfs_clear_password();
        password = strdup(passwd);
        struct timespec now;
        clock_gettime(CLOCK_BOOTTIME, &now);
        password_expiry_time = now.tv_sec + password_max_age_seconds;
    }

    return rc;
}

int cryptfs_verify_passwd(const char* passwd) {
    struct crypt_mnt_ftr crypt_ftr;
    unsigned char decrypted_master_key[MAX_KEY_LEN];
    char encrypted_state[PROPERTY_VALUE_MAX];
    int rc;

    property_get("ro.crypto.state", encrypted_state, "");
    if (strcmp(encrypted_state, "encrypted")) {
        SLOGE("device not encrypted, aborting");
        return -2;
    }

    if (!master_key_saved) {
        SLOGE("encrypted fs not yet mounted, aborting");
        return -1;
    }

    if (!saved_mount_point) {
        SLOGE("encrypted fs failed to save mount point, aborting");
        return -1;
    }

    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Error getting crypt footer and key\n");
        return -1;
    }

    if (crypt_ftr.flags & CRYPT_MNT_KEY_UNENCRYPTED) {
        /* If the device has no password, then just say the password is valid */
        rc = 0;
    } else {
#ifdef CONFIG_HW_DISK_ENCRYPTION
        if(is_hw_disk_encryption((char*)crypt_ftr.crypto_type_name)) {
            if (verify_hw_fde_passwd(passwd, &crypt_ftr) >= 0)
              rc = 0;
            else
              rc = -1;
        } else {
            decrypt_master_key(passwd, decrypted_master_key, &crypt_ftr, 0, 0);
            if (!memcmp(decrypted_master_key, saved_master_key, crypt_ftr.keysize)) {
                /* They match, the password is correct */
                rc = 0;
            } else {
              /* If incorrect, sleep for a bit to prevent dictionary attacks */
                sleep(1);
                rc = 1;
            }
        }
#else
        decrypt_master_key(passwd, decrypted_master_key, &crypt_ftr, 0, 0);
        if (!memcmp(decrypted_master_key, saved_master_key, crypt_ftr.keysize)) {
            /* They match, the password is correct */
            rc = 0;
        } else {
            /* If incorrect, sleep for a bit to prevent dictionary attacks */
            sleep(1);
            rc = 1;
        }
#endif
    }

    return rc;
}

/* Initialize a crypt_mnt_ftr structure.  The keysize is
 * defaulted to get_crypto_type().get_keysize() bytes, and the filesystem size to 0.
 * Presumably, at a minimum, the caller will update the
 * filesystem size and crypto_type_name after calling this function.
 */
static int cryptfs_init_crypt_mnt_ftr(struct crypt_mnt_ftr* ftr) {
    off64_t off;

    memset(ftr, 0, sizeof(struct crypt_mnt_ftr));
    ftr->magic = CRYPT_MNT_MAGIC;
    ftr->major_version = CURRENT_MAJOR_VERSION;
    ftr->minor_version = CURRENT_MINOR_VERSION;
    ftr->ftr_size = sizeof(struct crypt_mnt_ftr);
    ftr->keysize = get_crypto_type().get_keysize();
    ftr->kdf_type = KDF_SCRYPT_KEYMASTER;

    get_device_scrypt_params(ftr);

    ftr->persist_data_size = CRYPT_PERSIST_DATA_SIZE;
    if (get_crypt_ftr_info(NULL, &off) == 0) {
        ftr->persist_data_offset[0] = off + CRYPT_FOOTER_TO_PERSIST_OFFSET;
        ftr->persist_data_offset[1] = off + CRYPT_FOOTER_TO_PERSIST_OFFSET + ftr->persist_data_size;
    }

    return 0;
}

#define FRAMEWORK_BOOT_WAIT 60

static int vold_unmountAll(void) {
    VolumeManager* vm = VolumeManager::Instance();
    return vm->unmountAll();
}

int cryptfs_enable_internal(int crypt_type, const char* passwd, int no_ui) {
    std::string crypto_blkdev;
    std::string real_blkdev;
    unsigned char decrypted_master_key[MAX_KEY_LEN];
    int rc = -1, i;
    struct crypt_mnt_ftr crypt_ftr;
    struct crypt_persist_data* pdata;
    char encrypted_state[PROPERTY_VALUE_MAX];
    char lockid[32] = {0};
    std::string key_loc;
    int num_vols;
    bool rebootEncryption = false;
    bool onlyCreateHeader = false;
#ifdef CONFIG_HW_DISK_ENCRYPTION
    unsigned char newpw[32];
    int key_index = 0;
#endif
    int index = 0;

    /* Get a wakelock as this may take a while, and we don't want the
     * device to sleep on us.  We'll grab a partial wakelock, and if the UI
     * wants to keep the screen on, it can grab a full wakelock.
     */
    snprintf(lockid, sizeof(lockid), "enablecrypto%d", (int)getpid());
    auto wl = android::wakelock::WakeLock::tryGet(lockid);
    if (!wl.has_value()) {
        return android::UNEXPECTED_NULL;
    }

    if (get_crypt_ftr_and_key(&crypt_ftr) == 0) {
        if (crypt_ftr.flags & CRYPT_FORCE_ENCRYPTION) {
            if (!check_ftr_sha(&crypt_ftr)) {
                memset(&crypt_ftr, 0, sizeof(crypt_ftr));
                put_crypt_ftr_and_key(&crypt_ftr);
                goto error_unencrypted;
            }

            /* Doing a reboot-encryption*/
            crypt_ftr.flags &= ~CRYPT_FORCE_ENCRYPTION;
            crypt_ftr.flags |= CRYPT_FORCE_COMPLETE;
            rebootEncryption = true;
        }
    } else {
        // We don't want to accidentally reference invalid data.
        memset(&crypt_ftr, 0, sizeof(crypt_ftr));
    }

    property_get("ro.crypto.state", encrypted_state, "");
    if (!strcmp(encrypted_state, "encrypted")) {
        SLOGE("Device is already running encrypted, aborting");
        goto error_unencrypted;
    }

    get_crypt_info(&key_loc, &real_blkdev);

    /* Get the size of the real block device */
    uint64_t nr_sec;
    if (android::vold::GetBlockDev512Sectors(real_blkdev, &nr_sec) != android::OK) {
        SLOGE("Cannot get size of block device %s\n", real_blkdev.c_str());
        goto error_unencrypted;
    }

    /* If doing inplace encryption, make sure the orig fs doesn't include the crypto footer */
    if (key_loc == KEY_IN_FOOTER) {
        uint64_t fs_size_sec, max_fs_size_sec;
        fs_size_sec = get_fs_size(real_blkdev.c_str());
        if (fs_size_sec == 0) fs_size_sec = get_f2fs_filesystem_size_sec(real_blkdev.data());

        max_fs_size_sec = nr_sec - (CRYPT_FOOTER_OFFSET / CRYPT_SECTOR_SIZE);

        if (fs_size_sec > max_fs_size_sec) {
            SLOGE("Orig filesystem overlaps crypto footer region.  Cannot encrypt in place.");
            goto error_unencrypted;
        }
    }

    /* The init files are setup to stop the class main and late start when
     * vold sets trigger_shutdown_framework.
     */
    property_set("vold.decrypt", "trigger_shutdown_framework");
    SLOGD("Just asked init to shut down class main\n");

    /* Ask vold to unmount all devices that it manages */
    if (vold_unmountAll()) {
        SLOGE("Failed to unmount all vold managed devices");
    }

    /* no_ui means we are being called from init, not settings.
       Now we always reboot from settings, so !no_ui means reboot
     */
    if (!no_ui) {
        /* Try fallback, which is to reboot and try there */
        onlyCreateHeader = true;
        FILE* breadcrumb = fopen(BREADCRUMB_FILE, "we");
        if (breadcrumb == 0) {
            SLOGE("Failed to create breadcrumb file");
            goto error_shutting_down;
        }
        fclose(breadcrumb);
    }

    /* Do extra work for a better UX when doing the long inplace encryption */
    if (!onlyCreateHeader) {
        /* Now that /data is unmounted, we need to mount a tmpfs
         * /data, set a property saying we're doing inplace encryption,
         * and restart the framework.
         */
        wait_and_unmount(DATA_MNT_POINT);
        if (fs_mgr_do_tmpfs_mount(DATA_MNT_POINT)) {
            goto error_shutting_down;
        }
        /* Tells the framework that inplace encryption is starting */
        property_set("vold.encrypt_progress", "0");

        /* restart the framework. */
        /* Create necessary paths on /data */
        prep_data_fs();

        /* Ugh, shutting down the framework is not synchronous, so until it
         * can be fixed, this horrible hack will wait a moment for it all to
         * shut down before proceeding.  Without it, some devices cannot
         * restart the graphics services.
         */
        sleep(2);
    }

    /* Start the actual work of making an encrypted filesystem */
    /* Initialize a crypt_mnt_ftr for the partition */
    if (!rebootEncryption) {
        if (cryptfs_init_crypt_mnt_ftr(&crypt_ftr)) {
            goto error_shutting_down;
        }

        if (key_loc == KEY_IN_FOOTER) {
            crypt_ftr.fs_size = nr_sec - (CRYPT_FOOTER_OFFSET / CRYPT_SECTOR_SIZE);
        } else {
            crypt_ftr.fs_size = nr_sec;
        }
        /* At this point, we are in an inconsistent state. Until we successfully
           complete encryption, a reboot will leave us broken. So mark the
           encryption failed in case that happens.
           On successfully completing encryption, remove this flag */
        if (onlyCreateHeader) {
            crypt_ftr.flags |= CRYPT_FORCE_ENCRYPTION;
        } else {
            crypt_ftr.flags |= CRYPT_INCONSISTENT_STATE;
        }
        crypt_ftr.crypt_type = crypt_type;
#ifdef CONFIG_HW_DISK_ENCRYPTION
        strlcpy((char*)crypt_ftr.crypto_type_name, "aes-xts",
                MAX_CRYPTO_TYPE_NAME_LEN);
#else
        strlcpy((char*)crypt_ftr.crypto_type_name, get_crypto_type().get_kernel_name(),
                MAX_CRYPTO_TYPE_NAME_LEN);
#endif

        /* Make an encrypted master key */
        if (create_encrypted_random_key(onlyCreateHeader ? DEFAULT_PASSWORD : passwd,
                                        crypt_ftr.master_key, crypt_ftr.salt, &crypt_ftr)) {
            SLOGE("Cannot create encrypted master key\n");
            goto error_shutting_down;
        }

        /* Replace scrypted intermediate key if we are preparing for a reboot */
        if (onlyCreateHeader) {
            unsigned char fake_master_key[MAX_KEY_LEN];
            unsigned char encrypted_fake_master_key[MAX_KEY_LEN];
            memset(fake_master_key, 0, sizeof(fake_master_key));
            encrypt_master_key(passwd, crypt_ftr.salt, fake_master_key, encrypted_fake_master_key,
                               &crypt_ftr, true);
        }

        /* Write the key to the end of the partition */
        put_crypt_ftr_and_key(&crypt_ftr);

        /* If any persistent data has been remembered, save it.
         * If none, create a valid empty table and save that.
         */
        if (!persist_data) {
            pdata = (crypt_persist_data*)malloc(CRYPT_PERSIST_DATA_SIZE);
            if (pdata) {
                init_empty_persist_data(pdata, CRYPT_PERSIST_DATA_SIZE);
                persist_data = pdata;
            }
        }
        if (persist_data) {
            save_persistent_data();
        }
    }

    /* When encryption triggered from settings, encryption starts after reboot.
       So set the encryption key when the actual encryption starts.
     */
#ifdef CONFIG_HW_DISK_ENCRYPTION
    if (!rebootEncryption)
        clear_hw_device_encryption_key();

    if (get_keymaster_hw_fde_passwd(
                     onlyCreateHeader ? DEFAULT_PASSWORD : passwd,
                     newpw, crypt_ftr.salt, &crypt_ftr))
        key_index = set_hw_device_encryption_key(
                     onlyCreateHeader ? DEFAULT_PASSWORD : passwd,
                     (char*)crypt_ftr.crypto_type_name);
    else
        key_index = set_hw_device_encryption_key((const char*)newpw,
                            (char*) crypt_ftr.crypto_type_name);
    if (key_index < 0)
        goto error_shutting_down;

    crypt_ftr.flags |= CRYPT_ASCII_PASSWORD_UPDATED;
    put_crypt_ftr_and_key(&crypt_ftr);
#endif

    if (onlyCreateHeader) {
        sleep(2);
        cryptfs_reboot(RebootType::reboot);
    } else {
        /* Do extra work for a better UX when doing the long inplace encryption */
        /* Now that /data is unmounted, we need to mount a tmpfs
         * /data, set a property saying we're doing inplace encryption,
         * and restart the framework.
         */
        if (fs_mgr_do_tmpfs_mount(DATA_MNT_POINT)) {
            goto error_shutting_down;
        }
        /* Tells the framework that inplace encryption is starting */
        property_set("vold.encrypt_progress", "0");

        /* restart the framework. */
        /* Create necessary paths on /data */
        prep_data_fs();

        /* Ugh, shutting down the framework is not synchronous, so until it
         * can be fixed, this horrible hack will wait a moment for it all to
         * shut down before proceeding.  Without it, some devices cannot
         * restart the graphics services.
         */
        sleep(2);

        /* startup service classes main and late_start */
        property_set("vold.decrypt", "trigger_restart_min_framework");
        SLOGD("Just triggered restart_min_framework\n");

        /* OK, the framework is restarted and will soon be showing a
         * progress bar.  Time to setup an encrypted mapping, and
         * either write a new filesystem, or encrypt in place updating
         * the progress bar as we work.
         */
    }

    decrypt_master_key(passwd, decrypted_master_key, &crypt_ftr, 0, 0);
#ifdef CONFIG_HW_DISK_ENCRYPTION
    if (is_hw_disk_encryption((char*)crypt_ftr.crypto_type_name) && is_ice_enabled())
#ifdef CONFIG_HW_DISK_ENCRYPT_PERF
      crypto_blkdev = real_blkdev;
#else
      rc = create_crypto_blk_dev_hw(&crypt_ftr, (unsigned char*)&key_index, real_blkdev.c_str(),
                                 &crypto_blkdev, CRYPTO_BLOCK_DEVICE, 0);
#endif
    else
      rc = create_crypto_blk_dev_hw(&crypt_ftr, decrypted_master_key, real_blkdev.c_str(),
                                 &crypto_blkdev, CRYPTO_BLOCK_DEVICE, 0);
#else
    rc = create_crypto_blk_dev(&crypt_ftr, decrypted_master_key, real_blkdev.c_str(),
                               &crypto_blkdev, CRYPTO_BLOCK_DEVICE, 0);
#endif

#if defined(CONFIG_HW_DISK_ENCRYPTION) && defined(CONFIG_HW_DISK_ENCRYPT_PERF)
    if (set_ice_param(START_ENC)) {
        SLOGE("Failed to set ICE data");
        goto error_shutting_down;
    }
#endif
    if (!rc) {
        if (encrypt_inplace(crypto_blkdev, real_blkdev, crypt_ftr.fs_size, true)) {
            crypt_ftr.encrypted_upto = crypt_ftr.fs_size;
            rc = 0;
        } else {
            rc = -1;
        }
        /* Undo the dm-crypt mapping whether we succeed or not */
#if defined(CONFIG_HW_DISK_ENCRYPTION) && defined(CONFIG_HW_DISK_ENCRYPT_PERF)
    if (!is_ice_enabled())
       delete_crypto_blk_dev(CRYPTO_BLOCK_DEVICE);
#else
    delete_crypto_blk_dev(CRYPTO_BLOCK_DEVICE);
#endif
    }

#if defined(CONFIG_HW_DISK_ENCRYPTION) && defined(CONFIG_HW_DISK_ENCRYPT_PERF)
    if (set_ice_param(START_ENCDEC)) {
        SLOGE("Failed to set ICE data");
        goto error_shutting_down;
    }
#endif
    if (!rc) {
        /* Success */
        crypt_ftr.flags &= ~CRYPT_INCONSISTENT_STATE;

        put_crypt_ftr_and_key(&crypt_ftr);

        char value[PROPERTY_VALUE_MAX];
        property_get("ro.crypto.state", value, "");
        if (!strcmp(value, "")) {
            /* default encryption - continue first boot sequence */
            property_set("ro.crypto.state", "encrypted");
            property_set("ro.crypto.type", "block");
            wl.reset();
            if (rebootEncryption && crypt_ftr.crypt_type != CRYPT_TYPE_DEFAULT) {
                // Bring up cryptkeeper that will check the password and set it
                property_set("vold.decrypt", "trigger_shutdown_framework");
                sleep(2);
                property_set("vold.encrypt_progress", "");
                cryptfs_trigger_restart_min_framework();
            } else {
                cryptfs_check_passwd(DEFAULT_PASSWORD);
                cryptfs_restart_internal(1);
            }
            return 0;
        } else {
            sleep(2); /* Give the UI a chance to show 100% progress */
            cryptfs_reboot(RebootType::reboot);
        }
    } else {
        char value[PROPERTY_VALUE_MAX];

        property_get("ro.vold.wipe_on_crypt_fail", value, "0");
        if (!strcmp(value, "1")) {
            /* wipe data if encryption failed */
            SLOGE("encryption failed - rebooting into recovery to wipe data\n");
            std::string err;
            const std::vector<std::string> options = {
                "--wipe_data\n--reason=cryptfs_enable_internal\n"};
            if (!write_bootloader_message(options, &err)) {
                SLOGE("could not write bootloader message: %s", err.c_str());
            }
            cryptfs_reboot(RebootType::recovery);
        } else {
            /* set property to trigger dialog */
            property_set("vold.encrypt_progress", "error_partially_encrypted");
        }
        return -1;
    }

    /* hrm, the encrypt step claims success, but the reboot failed.
     * This should not happen.
     * Set the property and return.  Hope the framework can deal with it.
     */
    property_set("vold.encrypt_progress", "error_reboot_failed");
    return rc;

error_unencrypted:
    property_set("vold.encrypt_progress", "error_not_encrypted");
    return -1;

error_shutting_down:
    /* we failed, and have not encrypted anthing, so the users's data is still intact,
     * but the framework is stopped and not restarted to show the error, so it's up to
     * vold to restart the system.
     */
    SLOGE(
        "Error enabling encryption after framework is shutdown, no data changed, restarting "
        "system");
    cryptfs_reboot(RebootType::reboot);

    /* shouldn't get here */
    property_set("vold.encrypt_progress", "error_shutting_down");
    return -1;
}

int cryptfs_enable(int type, const char* passwd, int no_ui) {
    return cryptfs_enable_internal(type, passwd, no_ui);
}

int cryptfs_enable_default(int no_ui) {
    return cryptfs_enable_internal(CRYPT_TYPE_DEFAULT, DEFAULT_PASSWORD, no_ui);
}

int cryptfs_changepw(int crypt_type, const char* currentpw, const char* newpw) {
    if (fscrypt_is_native()) {
        SLOGE("cryptfs_changepw not valid for file encryption");
        return -1;
    }

    struct crypt_mnt_ftr crypt_ftr;
    int rc;

    /* This is only allowed after we've successfully decrypted the master key */
    if (!master_key_saved) {
        SLOGE("Key not saved, aborting");
        return -1;
    }

    if (crypt_type < 0 || crypt_type > CRYPT_TYPE_MAX_TYPE) {
        SLOGE("Invalid crypt_type %d", crypt_type);
        return -1;
    }

    /* get key */
    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Error getting crypt footer and key");
        return -1;
    }

#ifdef CONFIG_HW_DISK_ENCRYPTION
    if(is_hw_disk_encryption((char*)crypt_ftr.crypto_type_name))
        return  cryptfs_changepw_hw_fde(crypt_type, currentpw, newpw);
    else {
        crypt_ftr.crypt_type = crypt_type;

        rc = encrypt_master_key(crypt_type == CRYPT_TYPE_DEFAULT ?
                                     DEFAULT_PASSWORD : newpw,
                                     crypt_ftr.salt,
                                     saved_master_key,
                                     crypt_ftr.master_key,
                                     &crypt_ftr, false);
        if (rc) {
            SLOGE("Encrypt master key failed: %d", rc);
            return -1;
        }
        /* save the key */
        put_crypt_ftr_and_key(&crypt_ftr);

        return 0;
    }
#else
    crypt_ftr.crypt_type = crypt_type;

    rc = encrypt_master_key(crypt_type == CRYPT_TYPE_DEFAULT ? DEFAULT_PASSWORD : newpw,
                            crypt_ftr.salt, saved_master_key, crypt_ftr.master_key, &crypt_ftr,
                            false);
    if (rc) {
        SLOGE("Encrypt master key failed: %d", rc);
        return -1;
    }
    /* save the key */
    put_crypt_ftr_and_key(&crypt_ftr);

    return 0;
#endif
}

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

static unsigned int persist_get_max_entries(int encrypted) {
    struct crypt_mnt_ftr crypt_ftr;
    unsigned int dsize;

    /* If encrypted, use the values from the crypt_ftr, otherwise
     * use the values for the current spec.
     */
    if (encrypted) {
        if (get_crypt_ftr_and_key(&crypt_ftr)) {
            /* Something is wrong, assume no space for entries */
            return 0;
        }
        dsize = crypt_ftr.persist_data_size;
    } else {
        dsize = CRYPT_PERSIST_DATA_SIZE;
    }

    if (dsize > sizeof(struct crypt_persist_data)) {
        return (dsize - sizeof(struct crypt_persist_data)) / sizeof(struct crypt_persist_entry);
    } else {
        return 0;
    }
}

static int persist_get_key(const char* fieldname, char* value) {
    unsigned int i;

    if (persist_data == NULL) {
        return -1;
    }
    for (i = 0; i < persist_data->persist_valid_entries; i++) {
        if (!strncmp(persist_data->persist_entry[i].key, fieldname, PROPERTY_KEY_MAX)) {
            /* We found it! */
            strlcpy(value, persist_data->persist_entry[i].val, PROPERTY_VALUE_MAX);
            return 0;
        }
    }

    return -1;
}

static int persist_set_key(const char* fieldname, const char* value, int encrypted) {
    unsigned int i;
    unsigned int num;
    unsigned int max_persistent_entries;

    if (persist_data == NULL) {
        return -1;
    }

    max_persistent_entries = persist_get_max_entries(encrypted);

    num = persist_data->persist_valid_entries;

    for (i = 0; i < num; i++) {
        if (!strncmp(persist_data->persist_entry[i].key, fieldname, PROPERTY_KEY_MAX)) {
            /* We found an existing entry, update it! */
            memset(persist_data->persist_entry[i].val, 0, PROPERTY_VALUE_MAX);
            strlcpy(persist_data->persist_entry[i].val, value, PROPERTY_VALUE_MAX);
            return 0;
        }
    }

    /* We didn't find it, add it to the end, if there is room */
    if (persist_data->persist_valid_entries < max_persistent_entries) {
        memset(&persist_data->persist_entry[num], 0, sizeof(struct crypt_persist_entry));
        strlcpy(persist_data->persist_entry[num].key, fieldname, PROPERTY_KEY_MAX);
        strlcpy(persist_data->persist_entry[num].val, value, PROPERTY_VALUE_MAX);
        persist_data->persist_valid_entries++;
        return 0;
    }

    return -1;
}

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

/*
 * Delete entry/entries from persist_data. If the entries are part of a multi-segment field, all
 * remaining entries starting from index will be deleted.
 * returns PERSIST_DEL_KEY_OK if deletion succeeds,
 * PERSIST_DEL_KEY_ERROR_NO_FIELD if the field does not exist,
 * and PERSIST_DEL_KEY_ERROR_OTHER if error occurs.
 *
 */
static int persist_del_keys(const char* fieldname, unsigned index) {
    unsigned int i;
    unsigned int j;
    unsigned int num;

    if (persist_data == NULL) {
        return PERSIST_DEL_KEY_ERROR_OTHER;
    }

    num = persist_data->persist_valid_entries;

    j = 0;  // points to the end of non-deleted entries.
    // Filter out to-be-deleted entries in place.
    for (i = 0; i < num; i++) {
        if (!match_multi_entry(persist_data->persist_entry[i].key, fieldname, index)) {
            persist_data->persist_entry[j] = persist_data->persist_entry[i];
            j++;
        }
    }

    if (j < num) {
        persist_data->persist_valid_entries = j;
        // Zeroise the remaining entries
        memset(&persist_data->persist_entry[j], 0, (num - j) * sizeof(struct crypt_persist_entry));
        return PERSIST_DEL_KEY_OK;
    } else {
        // Did not find an entry matching the given fieldname
        return PERSIST_DEL_KEY_ERROR_NO_FIELD;
    }
}

static int persist_count_keys(const char* fieldname) {
    unsigned int i;
    unsigned int count;

    if (persist_data == NULL) {
        return -1;
    }

    count = 0;
    for (i = 0; i < persist_data->persist_valid_entries; i++) {
        if (match_multi_entry(persist_data->persist_entry[i].key, fieldname, 0)) {
            count++;
        }
    }

    return count;
}

/* Return the value of the specified field. */
int cryptfs_getfield(const char* fieldname, char* value, int len) {
    if (fscrypt_is_native()) {
        SLOGE("Cannot get field when file encrypted");
        return -1;
    }

    char temp_value[PROPERTY_VALUE_MAX];
    /* CRYPTO_GETFIELD_OK is success,
     * CRYPTO_GETFIELD_ERROR_NO_FIELD is value not set,
     * CRYPTO_GETFIELD_ERROR_BUF_TOO_SMALL is buffer (as given by len) too small,
     * CRYPTO_GETFIELD_ERROR_OTHER is any other error
     */
    int rc = CRYPTO_GETFIELD_ERROR_OTHER;
    int i;
    char temp_field[PROPERTY_KEY_MAX];

    if (persist_data == NULL) {
        load_persistent_data();
        if (persist_data == NULL) {
            SLOGE("Getfield error, cannot load persistent data");
            goto out;
        }
    }

    // Read value from persistent entries. If the original value is split into multiple entries,
    // stitch them back together.
    if (!persist_get_key(fieldname, temp_value)) {
        // We found it, copy it to the caller's buffer and keep going until all entries are read.
        if (strlcpy(value, temp_value, len) >= (unsigned)len) {
            // value too small
            rc = CRYPTO_GETFIELD_ERROR_BUF_TOO_SMALL;
            goto out;
        }
        rc = CRYPTO_GETFIELD_OK;

        for (i = 1; /* break explicitly */; i++) {
            if (snprintf(temp_field, sizeof(temp_field), "%s_%d", fieldname, i) >=
                (int)sizeof(temp_field)) {
                // If the fieldname is very long, we stop as soon as it begins to overflow the
                // maximum field length. At this point we have in fact fully read out the original
                // value because cryptfs_setfield would not allow fields with longer names to be
                // written in the first place.
                break;
            }
            if (!persist_get_key(temp_field, temp_value)) {
                if (strlcat(value, temp_value, len) >= (unsigned)len) {
                    // value too small.
                    rc = CRYPTO_GETFIELD_ERROR_BUF_TOO_SMALL;
                    goto out;
                }
            } else {
                // Exhaust all entries.
                break;
            }
        }
    } else {
        /* Sadness, it's not there.  Return the error */
        rc = CRYPTO_GETFIELD_ERROR_NO_FIELD;
    }

out:
    return rc;
}

/* Set the value of the specified field. */
int cryptfs_setfield(const char* fieldname, const char* value) {
    if (fscrypt_is_native()) {
        SLOGE("Cannot set field when file encrypted");
        return -1;
    }

    char encrypted_state[PROPERTY_VALUE_MAX];
    /* 0 is success, negative values are error */
    int rc = CRYPTO_SETFIELD_ERROR_OTHER;
    int encrypted = 0;
    unsigned int field_id;
    char temp_field[PROPERTY_KEY_MAX];
    unsigned int num_entries;
    unsigned int max_keylen;

    if (persist_data == NULL) {
        load_persistent_data();
        if (persist_data == NULL) {
            SLOGE("Setfield error, cannot load persistent data");
            goto out;
        }
    }

    property_get("ro.crypto.state", encrypted_state, "");
    if (!strcmp(encrypted_state, "encrypted")) {
        encrypted = 1;
    }

    // Compute the number of entries required to store value, each entry can store up to
    // (PROPERTY_VALUE_MAX - 1) chars
    if (strlen(value) == 0) {
        // Empty value also needs one entry to store.
        num_entries = 1;
    } else {
        num_entries = (strlen(value) + (PROPERTY_VALUE_MAX - 1) - 1) / (PROPERTY_VALUE_MAX - 1);
    }

    max_keylen = strlen(fieldname);
    if (num_entries > 1) {
        // Need an extra "_%d" suffix.
        max_keylen += 1 + log10(num_entries);
    }
    if (max_keylen > PROPERTY_KEY_MAX - 1) {
        rc = CRYPTO_SETFIELD_ERROR_FIELD_TOO_LONG;
        goto out;
    }

    // Make sure we have enough space to write the new value
    if (persist_data->persist_valid_entries + num_entries - persist_count_keys(fieldname) >
        persist_get_max_entries(encrypted)) {
        rc = CRYPTO_SETFIELD_ERROR_VALUE_TOO_LONG;
        goto out;
    }

    // Now that we know persist_data has enough space for value, let's delete the old field first
    // to make up space.
    persist_del_keys(fieldname, 0);

    if (persist_set_key(fieldname, value, encrypted)) {
        // fail to set key, should not happen as we have already checked the available space
        SLOGE("persist_set_key() error during setfield()");
        goto out;
    }

    for (field_id = 1; field_id < num_entries; field_id++) {
        snprintf(temp_field, sizeof(temp_field), "%s_%u", fieldname, field_id);

        if (persist_set_key(temp_field, value + field_id * (PROPERTY_VALUE_MAX - 1), encrypted)) {
            // fail to set key, should not happen as we have already checked the available space.
            SLOGE("persist_set_key() error during setfield()");
            goto out;
        }
    }

    /* If we are running encrypted, save the persistent data now */
    if (encrypted) {
        if (save_persistent_data()) {
            SLOGE("Setfield error, cannot save persistent data");
            goto out;
        }
    }

    rc = CRYPTO_SETFIELD_OK;

out:
    return rc;
}

/* Checks userdata. Attempt to mount the volume if default-
 * encrypted.
 * On success trigger next init phase and return 0.
 * Currently do not handle failure - see TODO below.
 */
int cryptfs_mount_default_encrypted(void) {
    int crypt_type = cryptfs_get_password_type();
    if (crypt_type < 0 || crypt_type > CRYPT_TYPE_MAX_TYPE) {
        SLOGE("Bad crypt type - error");
    } else if (crypt_type != CRYPT_TYPE_DEFAULT) {
        SLOGD(
            "Password is not default - "
            "starting min framework to prompt");
        property_set("vold.decrypt", "trigger_restart_min_framework");
        return 0;
    } else if (cryptfs_check_passwd(DEFAULT_PASSWORD) == 0) {
        SLOGD("Password is default - restarting filesystem");
        cryptfs_restart_internal(0);
        return 0;
    } else {
        SLOGE("Encrypted, default crypt type but can't decrypt");
    }

    /** Corrupt. Allow us to boot into framework, which will detect bad
        crypto when it calls do_crypto_complete, then do a factory reset
     */
    property_set("vold.decrypt", "trigger_restart_min_framework");
    return 0;
}

/* Returns type of the password, default, pattern, pin or password.
 */
int cryptfs_get_password_type(void) {
    if (fscrypt_is_native()) {
        SLOGE("cryptfs_get_password_type not valid for file encryption");
        return -1;
    }

    struct crypt_mnt_ftr crypt_ftr;

    if (get_crypt_ftr_and_key(&crypt_ftr)) {
        SLOGE("Error getting crypt footer and key\n");
        return -1;
    }

    if (crypt_ftr.flags & CRYPT_INCONSISTENT_STATE) {
        return -1;
    }

    return crypt_ftr.crypt_type;
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

int cryptfs_isConvertibleToFBE() {
    auto entry = GetEntryForMountPoint(&fstab_default, DATA_MNT_POINT);
    return entry && entry->fs_mgr_flags.force_fde_or_fbe;
}

int cryptfs_create_default_ftr(struct crypt_mnt_ftr* crypt_ftr, __attribute__((unused))int key_length)
{
    if (cryptfs_init_crypt_mnt_ftr(crypt_ftr)) {
        SLOGE("Failed to initialize crypt_ftr");
        return -1;
    }

    if (create_encrypted_random_key(DEFAULT_PASSWORD, crypt_ftr->master_key,
                                    crypt_ftr->salt, crypt_ftr)) {
        SLOGE("Cannot create encrypted master key\n");
        return -1;
    }

    //crypt_ftr->keysize = key_length / 8;
    return 0;
}
