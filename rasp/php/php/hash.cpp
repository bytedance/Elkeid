#include "hash.h"
#include <php_version.h>

zval *hashFind(const HashTable *hashTable, const char *key) {
#if PHP_MAJOR_VERSION > 5
    return zend_hash_str_find(hashTable, key, strlen(key));
#else
    zval **val;

    if (zend_hash_find(hashTable, key, strlen(key) + 1, (void **) &val) != SUCCESS)
        return nullptr;

    return *val;
#endif
}

HashIterator::HashIterator(HashTable *hashTable, HashPosition position) {
    mHashTable = hashTable;
    mPosition = position;
}

int HashIterator::keyType() {
    return zend_hash_get_current_key_type_ex(mHashTable, &mPosition);
}

std::variant<std::monostate, unsigned long, std::string> HashIterator::key() {
#if PHP_MAJOR_VERSION > 5
    zend_ulong index;
    zend_string *key;

    int type = zend_hash_get_current_key_ex(mHashTable, &key, &index, &mPosition);
#else
    ulong index;
    char *key;

    int type = zend_hash_get_current_key_ex(mHashTable, &key, nullptr, &index, 0, &mPosition);
#endif

    switch (type) {
        case HASH_KEY_IS_LONG:
            return index;

        case HASH_KEY_IS_STRING:
#if PHP_MAJOR_VERSION > 5
            return std::string{ZSTR_VAL(key), ZSTR_LEN(key)};
#else
            return std::string{key};
#endif

        default:
            break;
    }

    return {};
}

zval *HashIterator::value() {
#if PHP_MAJOR_VERSION > 5
    return zend_hash_get_current_data_ex(mHashTable, &mPosition);
#else
    zval **val;

    if (zend_hash_get_current_data_ex(mHashTable, (void **) &val, &mPosition) != SUCCESS)
        return nullptr;

    return *val;
#endif
}

Element HashIterator::operator*() {
    return {
            keyType(),
            key(),
            value()
    };
}

HashIterator &HashIterator::operator++() {
    zend_hash_move_forward_ex(mHashTable, &mPosition);
    return *this;
}

bool HashIterator::operator==(const HashIterator &it) {
    return mHashTable == it.mHashTable && mPosition == it.mPosition;
}

bool HashIterator::operator!=(const HashIterator &it) {
    return !operator==(it);
}

HashIterator begin(HashTable *hashTable) {
    HashPosition position;
    zend_hash_internal_pointer_reset_ex(hashTable, &position);

    return HashIterator(hashTable, position);
}

HashIterator end(HashTable *hashTable) {
    HashPosition position;

    zend_hash_internal_pointer_end_ex(hashTable, &position);
    zend_hash_move_forward_ex(hashTable, &position);

    return HashIterator(hashTable, position);
}
