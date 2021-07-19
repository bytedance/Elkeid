#ifndef GO_PROBE_PREPROCESS_H
#define GO_PROBE_PREPROCESS_H

#include <cstddef>
#include <array>
#include <type_traits>

namespace go {
    struct FieldMetadata {
        unsigned long offset;
        unsigned long size;
        bool floating;
    };

    template<std::size_t... I1s>
    struct ConcatHelper {
        template<typename T, std::size_t... I2s>
        static constexpr std::array<T, sizeof...(I1s) + sizeof...(I2s)>
                concat(
                        std::array<T, sizeof...(I1s)> const &lhs,
                        std::array<T, sizeof...(I2s)> const &rhs,
                        std::index_sequence<I2s...>
                                ) {
            return {lhs[I1s]..., rhs[I2s]...};
        }
    };

    template<std::size_t... I1s>
    ConcatHelper<I1s...> get_helper_type(std::index_sequence<I1s...>);

    template<typename T, std::size_t N1, std::size_t N2>
    constexpr std::array<T, N1 + N2> array_cat(std::array<T, N1> const &lhs, std::array<T, N2> const &rhs) {
        return decltype(get_helper_type(std::make_index_sequence<N1>{}))::concat(
                lhs,
                rhs,
                std::make_index_sequence<N2>{}
        );
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

    template<typename T>
    struct Metadata {
        static constexpr bool hasNonTrivialArray() {
            return is_non_trivial_array<T>::value;
        }

        static constexpr int getFloatRegister() {
            return std::is_floating_point<T>::value ||
                   std::is_same<T, float _Complex>::value ||
                   std::is_same<T, double _Complex>::value ? 1 : 0;
        }

        static constexpr int getIntegerRegister() {
            return std::is_floating_point<T>::value ||
                   std::is_same<T, float _Complex>::value ||
                   std::is_same<T, double _Complex>::value ||
                   is_non_trivial_array<T>::value ? 0 : 1;
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
                            std::is_floating_point<T>::value ||
                            std::is_same<T, float _Complex>::value ||
                            std::is_same<T, double _Complex>::value
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
            auto field = current.back();                                                                \
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
