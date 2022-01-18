<<<<<<< HEAD   (9349e6 keystorage: do not upgrade keys in TWRP)
#include <map>
#include <string>

#define CRYPT_TYPE_DEFAULT  1

// Store main DE/CE policy
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_de_policies;
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_ce_policies;
extern std::string de_key_raw_ref;
=======
#include <map>
#include <string>

#define CRYPT_TYPE_DEFAULT  1

// Store main DE/CE policy
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_de_policies;
extern std::map<userid_t, android::fscrypt::EncryptionPolicy> s_ce_policies;
extern std::string de_key_raw_ref;
>>>>>>> CHANGE (c0dab3 fscrypt: move functionality to libvold)
