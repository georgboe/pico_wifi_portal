#pragma once

// Shadows the host <malloc.h> so free-heap reporting is deterministic.
#include <cstddef>

struct mallinfo {
  size_t uordblks;
};

struct mallinfo mallinfo();
