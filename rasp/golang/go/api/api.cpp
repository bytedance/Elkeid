#include "api.h"

constexpr auto RASP_ERROR = "API blocked by RASP";

constexpr auto RASP_ERROR_STRING = go::string {
        RASP_ERROR,
        19
};

go::interface CAPIBase::error = {
        nullptr,
        (void *)&RASP_ERROR_STRING
};
