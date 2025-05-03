#include <map>
#include <string>

#define CRYPT_TYPE_DEFAULT  1

// Struct that holds the EncryptionPolicy for each CE or DE key that is currently installed
// (added to the kernel) for a particular user
struct UserPolicies {
    // Internal storage policy.  Exists whenever a user's UserPolicies exists at all, and used
    // instead of a map entry keyed by an empty UUID to make this invariant explicit.
    android::fscrypt::EncryptionPolicy internal;
    // Adoptable storage policies, indexed by (nonempty) volume UUID
    std::map<std::string, android::fscrypt::EncryptionPolicy> adoptable;
};

// The currently installed CE and DE keys for each user.  Protected by VolumeManager::mCryptLock.
extern std::map<userid_t, UserPolicies> s_ce_policies;
extern std::map<userid_t, UserPolicies> s_de_policies;
extern std::string de_key_raw_ref;
