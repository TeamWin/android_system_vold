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

#ifndef ANDROID_VOLD_CRYPTFS_H
#define ANDROID_VOLD_CRYPTFS_H

#include <string>

#include "KeyBuffer.h"
#include "KeyUtil.h"

int cryptfs_setup_ext_volume(const char* label, const char* real_blkdev,
                             const android::vold::KeyBuffer& key, std::string* out_crypto_blkdev);
int cryptfs_getfield(const char* fieldname, char* value, int len);
int cryptfs_setfield(const char* fieldname, const char* value);
int cryptfs_mount_default_encrypted(void);
int cryptfs_get_password_type(void);
int delete_crypto_blk_dev(const std::string& name);
const char* cryptfs_get_password(void);
void cryptfs_clear_password(void);
int cryptfs_isConvertibleToFBE(void);
const android::vold::KeyGeneration cryptfs_get_keygen();

#endif /* ANDROID_VOLD_CRYPTFS_H */
