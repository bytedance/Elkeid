#ifndef GO_PROBE_PREPROCESS_H
#define GO_PROBE_PREPROCESS_H

#include <cstddef>
#include <array>
#include <type_traits>

namespace go {
    template<unsigned int... Is>
    struct seq {};

    template<unsigned int N, unsigned int... Is>
    struct gen_seq : gen_seq<N - 1, N - 1, Is...> {};

    template<unsigned int... Is>
    struct gen_seq<0, Is...> : seq<Is...> {};

    template<typename T, size_t N1, unsigned int... I1, size_t N2, unsigned int... I2>
    constexpr std::array<T, N1 + N2>
    array_cat(const std::array<T, N1> &a1, const std::array<T, N2> &a2, seq<I1...>, seq<I2...>) {
        return {a1[I1]..., a2[I2]...};
    }

    template<typename T, size_t N1, size_t N2>
    constexpr std::array<T, N1 + N2> array_cat(const std::array<T, N1> &a1, const std::array<T, N2> &a2) {
        return array_cat(a1, a2, gen_seq<N1>{}, gen_seq<N2>{});
    }

    template<typename>
    struct is_non_trivial_array : public std::false_type {};

    template<typename T>
    struct is_non_trivial_array<T[0]> : public std::false_type {};

    template<typename T>
    struct is_non_trivial_array<T[1]> : public std::false_type {};

    template<typename T, std::size_t N>
    struct is_non_trivial_array<T[N]> : public std::true_type {};

    template<typename T>
    struct is_non_trivial_array<T[]> : public std::true_type {};

    struct FieldMetadata {
        unsigned long offset;
        unsigned long size;
        bool floating;
    };

    template<typename T>
    struct Metadata {
        static constexpr bool hasNonTrivialArray() {
            return is_non_trivial_array<T>::value;
        }

        static constexpr int getFloatRegister() {
            if (hasNonTrivialArray())
                return 0;

            return std::is_floating_point<T>::value ||
                   std::is_same<T, float _Complex>::value ||
                   std::is_same<T, double _Complex>::value ? 1 : 0;
        }

        static constexpr int getIntegerRegister() {
            if (hasNonTrivialArray())
                return 0;

            return getFloatRegister() ? 0 : 1;
        }

        static constexpr unsigned long getAlign() {
            return alignof(T);
        }

        static constexpr unsigned long getFieldNum() {
            return 1;
        }

        static constexpr std::array<FieldMetadata, 1> getFields(unsigned long offset = 0) {
            return std::array<FieldMetadata, 1> {
                    FieldMetadata{
                            offset + (offset % alignof(T) ? alignof(T) - offset % alignof(T) : 0),
                            sizeof(T),
                            getFloatRegister()
                    }
            };
        }

        static constexpr unsigned long getSize() {
            return sizeof(T);
        }
    };

#define TEMPLATE_ARG(...) __VA_ARGS__

#define TEMPLATE_METADATA(c, ...)                                                                       \
    struct Metadata<c> {                                                                                \
        static constexpr bool hasNonTrivialArray() {                                                    \
            return hasNonTrivialArray<__VA_ARGS__>();                                                   \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr bool hasNonTrivialArray() {                                                    \
            return hasNonTrivialArray<Current>() || hasNonTrivialArray<Next, Rest...>();                \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr bool hasNonTrivialArray() {                                                    \
            return Metadata<Current>::hasNonTrivialArray();                                             \
        }                                                                                               \
                                                                                                        \
        static constexpr int getFloatRegister() {                                                       \
            return getFloatRegister<__VA_ARGS__>();                                                     \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr int getFloatRegister() {                                                       \
            return Metadata<Current>::getFloatRegister() + getFloatRegister<Next, Rest...>();           \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr int getFloatRegister() {                                                       \
            return Metadata<Current>::getFloatRegister();                                               \
        }                                                                                               \
                                                                                                        \
        static constexpr int getIntegerRegister() {                                                     \
            return getIntegerRegister<__VA_ARGS__>();                                                   \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr int getIntegerRegister() {                                                     \
            return Metadata<Current>::getIntegerRegister() + getIntegerRegister<Next, Rest...>();       \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr int getIntegerRegister() {                                                     \
            return Metadata<Current>::getIntegerRegister();                                             \
        }                                                                                               \
                                                                                                        \
        static constexpr unsigned long getAlign() {                                                     \
            return getAlign<__VA_ARGS__>();                                                             \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr unsigned long getAlign() {                                                     \
            return std::max(getAlign<Current>(), getAlign<Next, Rest...>());                            \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr unsigned long getAlign() {                                                     \
            return Metadata<Current>::getAlign();                                                       \
        }                                                                                               \
                                                                                                        \
        static constexpr unsigned long getFieldNum() {                                                  \
            return getFieldNum<__VA_ARGS__>();                                                          \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr unsigned long getFieldNum() {                                                  \
            return getFieldNum<Current>() + getFieldNum<Next, Rest...>();                               \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr unsigned long getFieldNum() {                                                  \
            return Metadata<Current>::getFieldNum();                                                    \
        }                                                                                               \
                                                                                                        \
        static constexpr auto getFields(unsigned long offset = 0) {                                     \
            return getFields<__VA_ARGS__>(                                                              \
                    offset + (offset % getAlign() ? getAlign() - offset % getAlign() : 0)               \
                    );                                                                                  \
        }                                                                                               \
                                                                                                        \
        template<typename Current, typename Next, typename... Rest>                                     \
        static constexpr std::array<FieldMetadata, getFieldNum<Current, Next, Rest...>()>               \
                getFields(unsigned long offset) {                                                       \
            auto current = getFields<Current>(offset);                                                  \
            auto rest = getFields<Next, Rest...>(offset + Metadata<Current>::getSize());                \
                                                                                                        \
            return array_cat(current, rest);                                                            \
        }                                                                                               \
                                                                                                        \
        template<typename Current>                                                                      \
        static constexpr std::array<FieldMetadata, getFieldNum<Current>()>                              \
                getFields(unsigned long offset) {                                                       \
            return Metadata<Current>::getFields(offset);                                                \
        }                                                                                               \
                                                                                                        \
        static unsigned long getSize() {                                                                \
            auto fields = getFields();                                                                  \
            auto align = getAlign();                                                                    \
                                                                                                        \
            auto last = fields.back();                                                                  \
            auto boundary = last.offset + last.size;                                                    \
                                                                                                        \
            return boundary + (boundary % align ? align - boundary % align : 0);                        \
        }                                                                                               \
    };

#define METADATA(c, ...)                                                                                \
    template<>                                                                                          \
    TEMPLATE_METADATA(c, __VA_ARGS__)
}

#endif //GO_PROBE_PREPROCESS_H
