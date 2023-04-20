#ifndef GO_PROBE_PREPROCESS_H
#define GO_PROBE_PREPROCESS_H

#include <cstddef>
#include <array>
#include <tuple>
#include <algorithm>
#include <type_traits>

namespace go {
    template<typename T, std::size_t... sizes>
    constexpr auto array_cat(const std::array<T, sizes> &... arrays) {
        return std::apply(
                [](auto... elems) -> std::array<T, (sizes + ...)> {
                    return {{elems...}};
                },
                std::tuple_cat(std::tuple_cat(arrays)...)
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

    struct Field {
        size_t offset;
        size_t size;
        bool floating;
    };

    template<typename T>
    struct Metadata {
        static constexpr bool hasNonTrivialArray = is_non_trivial_array<T>::value;
        static constexpr int NFP = hasNonTrivialArray ? 0 : (std::is_floating_point<T>::value ||
                                                             std::is_same<T, float _Complex>::value ||
                                                             std::is_same<T, double _Complex>::value ? 1 : 0);
        static constexpr int NI = hasNonTrivialArray ? 0 : (NFP ? 0 : 1);

        static constexpr size_t align = alignof(T);
        static constexpr size_t fieldNum = 1;
        static constexpr size_t size = sizeof(T);

        static constexpr auto getFields(size_t offset = 0) {
            return std::array<Field, 1> {
                    Field{
                            offset + (offset % align ? align - (offset % align) : 0),
                            size,
                            NFP != 0
                    }
            };
        }
    };

    template<typename ...Ts>
    constexpr bool hasAnyNonTrivialArray() {
        return (Metadata<Ts>::hasNonTrivialArray || ...);
    }

    template<typename ...Ts>
    constexpr int sumNFP() {
        return (Metadata<Ts>::NFP + ...);
    }

    template<typename ...Ts>
    constexpr int sumNI() {
        return (Metadata<Ts>::NI + ...);
    }

    template<typename ...Ts>
    constexpr size_t sumFieldNum() {
        return (Metadata<Ts>::fieldNum + ...);
    }

    template<typename ...Ts>
    constexpr size_t maxAlign() {
        return std::max({Metadata<Ts>::align ...});
    }

    template<typename Current>
    constexpr auto concatFields(size_t offset) {
        return Metadata<Current>::getFields(offset);
    }

    template<typename Current, typename Next, typename... Rest>
    constexpr auto concatFields(size_t offset) {
        auto current = concatFields<Current>(offset);
        auto rest = concatFields<Next, Rest...>(current.back().offset + current.back().size);

        return array_cat(current, rest);
    }

    template<typename ...Ts>
    constexpr size_t calculateSize() {
        Field last = concatFields<Ts...>(0).back();

        size_t align = maxAlign<Ts...>();
        size_t boundary = last.offset + last.size;

        return boundary + (boundary % align ? align - (boundary % align) : 0);
    }

#define TEMPLATE_ARG(...) __VA_ARGS__

#define TEMPLATE_METADATA(c, ...)                                                                       \
    struct Metadata<c> {                                                                                \
        static constexpr bool hasNonTrivialArray = hasAnyNonTrivialArray<__VA_ARGS__>();                \
        static constexpr int NFP = sumNFP<__VA_ARGS__>();                                               \
        static constexpr int NI = sumNI<__VA_ARGS__>();                                                 \
        static constexpr size_t align = maxAlign<__VA_ARGS__>();                                        \
        static constexpr size_t fieldNum = sumFieldNum<__VA_ARGS__>();                                  \
                                                                                                        \
        static constexpr auto getFields(size_t offset = 0) {                                            \
            return concatFields<__VA_ARGS__>(offset + (offset % align ? align - (offset % align) : 0)); \
        }                                                                                               \
                                                                                                        \
        static constexpr size_t size = calculateSize<__VA_ARGS__>();                                    \
    };                                                                                                  \

#define METADATA(c, ...)                                                                                \
    template<>                                                                                          \
    TEMPLATE_METADATA(c, __VA_ARGS__)
}

#endif //GO_PROBE_PREPROCESS_H
