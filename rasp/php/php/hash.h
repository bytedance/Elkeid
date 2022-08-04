#ifndef PHP_PROBE_HASH_H
#define PHP_PROBE_HASH_H

#include <Zend/zend_API.h>
#include <variant>
#include <string>

zval *hashFind(const HashTable *hashTable, const char *key);

struct Element {
    int type;
    std::variant<std::monostate, unsigned long, std::string> key;
    zval *value;
};

class HashIterator {
public:
    explicit HashIterator(HashTable *hashTable, HashPosition position);

public:
    int keyType();
    std::variant<std::monostate, unsigned long, std::string> key();

public:
    zval *value();

public:
    Element operator*();
    HashIterator &operator++();

public:
    bool operator==(const HashIterator &it);
    bool operator!=(const HashIterator &it);

private:
    HashTable *mHashTable;
    HashPosition mPosition;
};

HashIterator begin(HashTable *hashTable);
HashIterator end(HashTable *hashTable);

#endif //PHP_PROBE_HASH_H
