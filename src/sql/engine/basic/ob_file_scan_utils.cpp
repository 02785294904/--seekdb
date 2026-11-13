/**
 * Copyright (c) 2025 OceanBase.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define USING_LOG_PREFIX SQL_ENG
#include "ob_file_scan_utils.h"
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common/timezone/ob_time_convert.h"
#include "sql/resolver/ob_resolver_utils.h"

namespace oceanbase
{
using namespace common;
namespace sql
{

int ObFileScanUtils::resolve_and_check_path(
    const common::ObString &raw_path,
    const common::ObString &secure_file_priv,
    const bool skip_priv_check,
    char *buf,
    const int64_t buf_len,
    common::ObString &real_path)
{
  int ret = OB_SUCCESS;
  real_path.reset();
  if (OB_ISNULL(buf) || buf_len <= 0 || raw_path.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid file path", K(ret), K(raw_path), KP(buf), K(buf_len));
  } else if (raw_path.length() >= PATH_MAX) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("file path is too long", K(ret), "length", raw_path.length());
  } else {
    // realpath() resolves every symlink, so the boundary check below sees the
    // same path the kernel will open.
    char cstyle[PATH_MAX];
    char resolved[PATH_MAX];
    struct stat stat_result;
    MEMCPY(cstyle, raw_path.ptr(), raw_path.length());
    cstyle[raw_path.length()] = '\0';
    if (OB_ISNULL(::realpath(cstyle, resolved))) {
      ret = OB_FILE_NOT_EXIST;
      LOG_WARN("failed to resolve file path", K(ret), K(raw_path), "errno", errno);
    } else {
      const int64_t resolved_len = STRLEN(resolved);
      if (resolved_len >= buf_len) {
        ret = OB_SIZE_OVERFLOW;
        LOG_WARN("resolved path does not fit", K(ret), K(resolved_len), K(buf_len));
      } else if (!skip_priv_check
                 && OB_FAIL(ObResolverUtils::check_secure_path(
                        secure_file_priv, common::ObString(resolved_len, resolved)))) {
        LOG_WARN("path is not allowed by secure_file_priv", K(ret),
                 K(secure_file_priv), "resolved_path", resolved);
      } else if (0 != ::stat(resolved, &stat_result)) {
        ret = OB_FILE_NOT_EXIST;
        LOG_WARN("failed to stat file", K(ret), "resolved_path", resolved, "errno", errno);
      } else if (!S_ISREG(stat_result.st_mode)) {
        ret = OB_INVALID_ARGUMENT;
        LOG_USER_ERROR(OB_INVALID_ARGUMENT, "file sql input is not a regular file");
        LOG_WARN("not a regular file", K(ret), "resolved_path", resolved);
      } else {
        MEMCPY(buf, resolved, resolved_len);
        buf[resolved_len] = '\0';
        real_path.assign_ptr(buf, resolved_len);
      }
    }
  }
  return ret;
}

int ObFileScanUtils::check_file_count(const int64_t match_count)
{
  int ret = OB_SUCCESS;
  if (match_count > ObFileScanLimits::MAX_FILE_COUNT) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("too many files matched", K(ret), K(match_count),
             "limit", ObFileScanLimits::MAX_FILE_COUNT);
  }
  return ret;
}

int ObFileScanUtils::check_column_count(const int64_t column_count)
{
  int ret = OB_SUCCESS;
  if (column_count > ObFileScanLimits::MAX_COLUMN_COUNT) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("too many columns", K(ret), K(column_count),
             "limit", ObFileScanLimits::MAX_COLUMN_COUNT);
  }
  return ret;
}

// A file table has no index, no default and nothing in the "extra" slot, but a
// client reading a DESCRIBE result expects all six columns to be there.
static const char *const FILE_TABLE_DESCRIBE_COLS[] = {
    "column_name", "column_type", "null", "key", "default", "extra"};
static_assert(sizeof(FILE_TABLE_DESCRIBE_COLS) / sizeof(FILE_TABLE_DESCRIBE_COLS[0])
                  == ObFileScanUtils::DESCRIBE_COLUMN_COUNT,
              "describe column names out of sync with the column count");

const char *ObFileScanUtils::describe_column_name(const int64_t idx)
{
  return FILE_TABLE_DESCRIBE_COLS[idx];
}

bool ObFileScanUtils::has_wildcard(const common::ObString &pattern)
{
  bool found = false;
  for (int64_t i = 0; !found && i < pattern.length(); ++i) {
    const char c = pattern.ptr()[i];
    found = ('*' == c || '?' == c || '[' == c);
  }
  return found;
}

int ObFileScanUtils::resolve_and_check_dir(
    const common::ObString &raw_dir,
    const common::ObString &secure_file_priv,
    const bool skip_priv_check,
    char *buf,
    const int64_t buf_len,
    common::ObString &real_dir)
{
  int ret = OB_SUCCESS;
  real_dir.reset();
  if (OB_ISNULL(buf) || buf_len <= 0 || raw_dir.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid directory", K(ret), K(raw_dir), KP(buf), K(buf_len));
  } else if (raw_dir.length() >= PATH_MAX) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("directory is too long", K(ret), "length", raw_dir.length());
  } else {
    char cstyle[PATH_MAX];
    char resolved[PATH_MAX];
    struct stat stat_result;
    MEMCPY(cstyle, raw_dir.ptr(), raw_dir.length());
    cstyle[raw_dir.length()] = '\0';
    if (OB_ISNULL(::realpath(cstyle, resolved))) {
      ret = OB_FILE_NOT_EXIST;
      LOG_WARN("failed to resolve directory", K(ret), K(raw_dir), "errno", errno);
    } else {
      const int64_t resolved_len = STRLEN(resolved);
      if (resolved_len >= buf_len) {
        ret = OB_SIZE_OVERFLOW;
        LOG_WARN("resolved directory does not fit", K(ret), K(resolved_len), K(buf_len));
      } else if (!skip_priv_check
                 && OB_FAIL(ObResolverUtils::check_secure_path(
                        secure_file_priv, common::ObString(resolved_len, resolved)))) {
        LOG_WARN("directory is not allowed by secure_file_priv", K(ret),
                 K(secure_file_priv), "resolved_dir", resolved);
      } else if (0 != ::stat(resolved, &stat_result)) {
        ret = OB_FILE_NOT_EXIST;
        LOG_WARN("failed to stat directory", K(ret), "resolved_dir", resolved, "errno", errno);
      } else if (!S_ISDIR(stat_result.st_mode)) {
        ret = OB_INVALID_ARGUMENT;
        LOG_USER_ERROR(OB_INVALID_ARGUMENT, "glob pattern prefix is not a directory");
        LOG_WARN("not a directory", K(ret), "resolved_dir", resolved);
      } else {
        MEMCPY(buf, resolved, resolved_len);
        buf[resolved_len] = '\0';
        real_dir.assign_ptr(buf, resolved_len);
      }
    }
  }
  return ret;
}

int ObFileScanUtils::list_matching_files(
    common::ObIAllocator &alloc,
    const common::ObString &pattern,
    const common::ObString &secure_file_priv,
    const bool skip_priv_check,
    common::ObIArray<common::ObString> &files)
{
  int ret = OB_SUCCESS;
  files.reuse();
  if (pattern.empty() || pattern.length() >= PATH_MAX) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid glob pattern", K(ret), K(pattern));
  } else if (!has_wildcard(pattern)) {
    // a pattern without meta characters names exactly one file
    char resolved_buf[PATH_MAX];
    common::ObString real_path;
    if (OB_FAIL(resolve_and_check_path(pattern, secure_file_priv, skip_priv_check,
                                       resolved_buf, sizeof(resolved_buf), real_path))) {
      LOG_WARN("failed to check file path", K(ret), K(pattern));
    } else if (OB_FAIL(ob_write_string(alloc, real_path, real_path))) {
      LOG_WARN("failed to copy file path", K(ret), K(real_path));
    } else if (OB_FAIL(files.push_back(real_path))) {
      LOG_WARN("failed to push file path", K(ret), K(real_path));
    }
  } else {
    // only the literal directory prefix before the first meta character is
    // bounded by secure_file_priv; glob() then expands the remaining pattern
    int64_t sep = -1;
    for (int64_t i = pattern.length() - 1; i >= 0 && sep < 0; --i) {
      if ('/' == pattern.ptr()[i]) { sep = i; }
    }
    const common::ObString raw_dir = sep < 0
        ? common::ObString(".") : common::ObString(sep, pattern.ptr());
    const common::ObString rest(sep < 0 ? pattern.length() : pattern.length() - sep - 1,
                                pattern.ptr() + (sep < 0 ? 0 : sep + 1));
    char dir_buf[PATH_MAX];
    common::ObString real_dir;
    if (rest.empty()) {
      ret = OB_INVALID_ARGUMENT;
      LOG_WARN("glob pattern has no file part", K(ret), K(pattern));
    } else if (OB_FAIL(resolve_and_check_dir(raw_dir, secure_file_priv, skip_priv_check,
                                             dir_buf, sizeof(dir_buf), real_dir))) {
      LOG_WARN("failed to check glob directory", K(ret), K(raw_dir));
    } else {
      char full_pattern[PATH_MAX];
      const int written = ::snprintf(full_pattern, sizeof(full_pattern), "%.*s/%.*s",
                                     real_dir.length(), real_dir.ptr(),
                                     rest.length(), rest.ptr());
      if (written < 0 || written >= static_cast<int>(sizeof(full_pattern))) {
        ret = OB_SIZE_OVERFLOW;
        LOG_WARN("expanded glob pattern is too long", K(ret), K(real_dir), K(rest));
      } else {
        glob_t glob_result;
        MEMSET(&glob_result, 0, sizeof(glob_result));
        const int gerr = ::glob(full_pattern, 0, NULL, &glob_result);
        if (0 != gerr) {
          ret = GLOB_NOMATCH == gerr ? OB_FILE_NOT_EXIST : OB_INVALID_ARGUMENT;
          LOG_WARN("failed to expand glob pattern", K(ret), K(full_pattern), K(gerr));
        } else if (OB_FAIL(check_file_count(static_cast<int64_t>(glob_result.gl_pathc)))) {
          LOG_WARN("too many files matched", K(ret), "count", glob_result.gl_pathc);
        } else {
          for (int64_t i = 0; OB_SUCC(ret) && i < static_cast<int64_t>(glob_result.gl_pathc); ++i) {
            const char *match = glob_result.gl_pathv[i];
            const common::ObString raw_match(STRLEN(match), const_cast<char *>(match));
            char resolved_buf[PATH_MAX];
            common::ObString real_path;
            if (OB_FAIL(resolve_and_check_path(raw_match, secure_file_priv, skip_priv_check,
                                               resolved_buf, sizeof(resolved_buf), real_path))) {
              // a match outside the boundary or not a regular file is not readable
              LOG_WARN("skip or fail on matched file", K(ret), K(raw_match));
            } else if (OB_FAIL(ob_write_string(alloc, real_path, real_path))) {
              LOG_WARN("failed to copy matched path", K(ret), K(real_path));
            } else if (OB_FAIL(files.push_back(real_path))) {
              LOG_WARN("failed to push matched path", K(ret), K(real_path));
            }
          }
        }
        ::globfree(&glob_result);
      }
    }
  }
  if (OB_SUCC(ret) && files.empty()) {
    ret = OB_FILE_NOT_EXIST;
    LOG_WARN("no file matched", K(ret), K(pattern));
  }
  return ret;
}

int ObFileScanUtils::read_csv_header(
    common::ObIAllocator &alloc,
    const common::ObString &real_path,
    const ObCsvScanOptions &options,
    common::ObIArray<common::ObString> &names)
{
  int ret = OB_SUCCESS;
  names.reuse();
  ObFileInput input;
  ObCsvScanner scanner;
  common::ObSEArray<ObFileScanColumnDef, 1> no_columns;
  common::ObSEArray<common::ObString, 16> fields;
  scanner.set_with_header(false);
  scanner.set_options(options);
  if (real_path.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid resolved path", K(ret), K(real_path));
  } else if (OB_FAIL(input.open(alloc, real_path))) {
    LOG_WARN("failed to open file for header", K(ret), K(real_path));
  } else if (OB_FAIL(scanner.open(input, no_columns))) {
    LOG_WARN("failed to open csv scanner", K(ret), K(real_path));
  } else if (OB_FAIL(scanner.next_row(fields))) {
    if (OB_ITER_END == ret) {
      ret = OB_SUCCESS;
    } else {
      LOG_WARN("failed to read the first record", K(ret), K(real_path),
               "error_pos", scanner.get_last_error_pos());
    }
  } else {
    for (int64_t i = 0; OB_SUCC(ret) && i < fields.count(); ++i) {
      common::ObString name = fields.at(i);
      if (OB_ISNULL(name.ptr())) {
        name.reset();
      } else if (OB_FAIL(ob_write_string(alloc, name, name))) {
        LOG_WARN("failed to copy column name", K(ret), K(name));
      }
      if (OB_FAIL(ret)) {
      } else if (OB_FAIL(names.push_back(name))) {
        LOG_WARN("failed to push column name", K(ret), K(name));
      }
    }
  }
  scanner.close();
  input.close();
  return ret;
}

namespace
{
const int64_t FILE_USECS_PER_HOUR = 3600LL * 1000000LL;
const int64_t FILE_USECS_PER_MINUTE = 60LL * 1000000LL;
const int64_t FILE_USECS_PER_SECOND = 1000000LL;
const int64_t FILE_INT64_MAX = 9223372036854775807LL;
const int64_t FILE_MAX_NUMERIC_TEXT = 128;

inline bool is_file_digit(const char c)
{
  return c >= '0' && c <= '9';
}

// Exactly len digits, no sign, no leftover characters.
inline bool read_fixed_digits(const char *text, const int64_t len, int64_t &value)
{
  bool bool_ret = true;
  value = 0;
  for (int64_t i = 0; bool_ret && i < len; ++i) {
    if (!is_file_digit(text[i])) {
      bool_ret = false;
    } else {
      value = value * 10 + (text[i] - '0');
    }
  }
  return bool_ret;
}

inline bool is_leap_year(const int64_t year)
{
  return (0 == year % 4 && 0 != year % 100) || 0 == year % 400;
}

inline int64_t days_of_month(const int64_t year, const int64_t month)
{
  static const int64_t DAYS[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  int64_t days = 0;
  if (month >= 1 && month <= 12) {
    days = DAYS[month - 1];
    if (2 == month && is_leap_year(year)) {
      days = 29;
    }
  }
  return days;
}

// The date prefix both the date and the datetime shape start with:
// YYYY-MM-DD, every part inside its legal range.
bool read_date_parts(const char *text, int64_t &year, int64_t &month, int64_t &day)
{
  bool bool_ret = false;
  int64_t y = 0;
  int64_t m = 0;
  int64_t d = 0;
  if (read_fixed_digits(text, 4, y) && '-' == text[4]
      && read_fixed_digits(text + 5, 2, m) && '-' == text[7]
      && read_fixed_digits(text + 8, 2, d)
      && y >= 0 && y <= 9999 && m >= 1 && m <= 12
      && d >= 1 && d <= days_of_month(y, m)) {
    year = y;
    month = m;
    day = d;
    bool_ret = true;
  }
  return bool_ret;
}
} // end anonymous namespace

bool ObFileValueParser::parse_boolean(const common::ObString &text, int64_t &value)
{
  bool bool_ret = false;
  value = 0;
  if (4 == text.length() && 0 == strncasecmp(text.ptr(), "true", 4)) {
    value = 1;
    bool_ret = true;
  } else if (5 == text.length() && 0 == strncasecmp(text.ptr(), "false", 5)) {
    bool_ret = true;
  }
  return bool_ret;
}

bool ObFileValueParser::parse_bigint(const common::ObString &text, int64_t &value)
{
  bool bool_ret = false;
  value = 0;
  const char *p = text.ptr();
  const int64_t len = text.length();
  int64_t i = 0;
  bool negative = false;
  uint64_t magnitude = 0;
  bool overflow = false;
  int64_t digits = 0;
  if (len <= 0) {
    // an empty field is not a number
  } else {
    if ('+' == p[0] || '-' == p[0]) {
      negative = ('-' == p[0]);
      i = 1;
    }
    for (; i < len && !overflow; ++i) {
      if (!is_file_digit(p[i])) {
        overflow = true;
      } else {
        const uint64_t digit = static_cast<uint64_t>(p[i] - '0');
        if (magnitude > (UINT64_MAX - digit) / 10) {
          overflow = true;
        } else {
          magnitude = magnitude * 10 + digit;
          ++digits;
        }
      }
    }
    if (i == len && !overflow && digits > 0) {
      const uint64_t limit = negative
                             ? static_cast<uint64_t>(FILE_INT64_MAX) + 1
                             : static_cast<uint64_t>(FILE_INT64_MAX);
      if (magnitude <= limit) {
        value = negative ? -static_cast<int64_t>(magnitude)
                         : static_cast<int64_t>(magnitude);
        if (negative && magnitude == limit) {
          value = INT64_MIN;
        }
        bool_ret = true;
      }
    }
  }
  return bool_ret;
}

bool ObFileValueParser::parse_double(const common::ObString &text, double &value)
{
  bool bool_ret = false;
  value = 0;
  const char *p = text.ptr();
  const int64_t len = text.length();
  int64_t i = 0;
  int64_t int_digits = 0;
  int64_t frac_digits = 0;
  int64_t exp_digits = 0;
  bool has_exp = false;
  if (len <= 0 || len > FILE_MAX_NUMERIC_TEXT) {
    // nothing to do, a literal that long reads as a string
  } else {
    if ('+' == p[0] || '-' == p[0]) {
      i = 1;
    }
    while (i < len && is_file_digit(p[i])) {
      ++int_digits;
      ++i;
    }
    if (i < len && '.' == p[i]) {
      ++i;
      while (i < len && is_file_digit(p[i])) {
        ++frac_digits;
        ++i;
      }
    }
    if (i < len && ('e' == p[i] || 'E' == p[i])) {
      has_exp = true;
      ++i;
      if (i < len && ('+' == p[i] || '-' == p[i])) {
        ++i;
      }
      while (i < len && is_file_digit(p[i])) {
        ++exp_digits;
        ++i;
      }
    }
    // a column that reads as DOUBLE holds whatever the file put in it, so plain
    // integers are values too; only recognise() has to tell them apart, and it
    // tries BIGINT before this function
    if (i == len && int_digits + frac_digits > 0
        && (!has_exp || exp_digits > 0)) {
      char buf[FILE_MAX_NUMERIC_TEXT + 1];
      char *end = NULL;
      MEMCPY(buf, p, len);
      buf[len] = '\0';
      const double parsed = ::strtod(buf, &end);
      if (NULL != end && '\0' == *end && isfinite(parsed)) {
        value = parsed;
        bool_ret = true;
      }
    }
  }
  return bool_ret;
}

bool ObFileValueParser::parse_date(const common::ObString &text, int32_t &value)
{
  bool bool_ret = false;
  value = 0;
  int64_t year = 0;
  int64_t month = 0;
  int64_t day = 0;
  if (10 == text.length() && NULL != text.ptr() && read_date_parts(text.ptr(), year, month, day)) {
    value = common::ObTimeConverter::calc_date(year, month, day);
    bool_ret = true;
  }
  return bool_ret;
}

bool ObFileValueParser::parse_datetime(const common::ObString &text,
                                       int64_t &value,
                                       int8_t &scale)
{
  bool bool_ret = false;
  value = 0;
  scale = 0;
  const char *p = text.ptr();
  const int64_t len = text.length();
  int64_t year = 0;
  int64_t month = 0;
  int64_t day = 0;
  int64_t hour = 0;
  int64_t minute = 0;
  int64_t second = 0;
  if (len >= 19 && len <= 26 && NULL != p
      && read_date_parts(p, year, month, day)
      && (' ' == p[10] || 'T' == p[10])
      && read_fixed_digits(p + 11, 2, hour) && ':' == p[13]
      && read_fixed_digits(p + 14, 2, minute) && ':' == p[16]
      && read_fixed_digits(p + 17, 2, second)
      && hour <= 23 && minute <= 59 && second <= 59) {
    int64_t usec = 0;
    int64_t pos = 19;
    bool ok = true;
    if (pos < len) {
      if ('.' != p[pos]) {
        ok = false;
      } else {
        ++pos;
        int64_t frac = 0;
        int64_t digits = 0;
        while (pos < len && digits < 6 && is_file_digit(p[pos])) {
          frac = frac * 10 + (p[pos] - '0');
          ++pos;
          ++digits;
        }
        if (0 == digits || pos != len) {
          ok = false;
        } else {
          scale = static_cast<int8_t>(digits);
          while (digits < 6) {
            frac *= 10;
            ++digits;
          }
          usec = frac;
        }
      }
    }
    if (ok) {
      value = static_cast<int64_t>(common::ObTimeConverter::calc_date(year, month, day))
              * common::USECS_PER_DAY
              + hour * FILE_USECS_PER_HOUR + minute * FILE_USECS_PER_MINUTE
              + second * FILE_USECS_PER_SECOND + usec;
      bool_ret = true;
    }
  }
  return bool_ret;
}

ObFileValueType ObFileValueParser::recognize(const common::ObString &text)
{
  int64_t number = 0;
  double dbl = 0;
  int32_t date = 0;
  int64_t datetime = 0;
  int8_t scale = 0;
  ObFileValueType type = FILE_VALUE_VARCHAR;
  if (parse_boolean(text, number)) {
    type = FILE_VALUE_BOOLEAN;
  } else if (parse_bigint(text, number)) {
    type = FILE_VALUE_BIGINT;
  } else if (parse_double(text, dbl)) {
    type = FILE_VALUE_DOUBLE;
  } else if (parse_date(text, date)) {
    type = FILE_VALUE_DATE;
  } else if (parse_datetime(text, datetime, scale)) {
    type = FILE_VALUE_DATETIME;
  }
  return type;
}

ObFileValueType ObFileValueParser::merge(const ObFileValueType left, const ObFileValueType right)
{
  ObFileValueType type = FILE_VALUE_VARCHAR;
  if (FILE_VALUE_UNKNOWN == left) {
    type = right;
  } else if (FILE_VALUE_UNKNOWN == right) {
    type = left;
  } else if (left == right) {
    type = left;
  } else if ((FILE_VALUE_BIGINT == left && FILE_VALUE_DOUBLE == right)
             || (FILE_VALUE_DOUBLE == left && FILE_VALUE_BIGINT == right)) {
    type = FILE_VALUE_DOUBLE;
  } else if ((FILE_VALUE_DATE == left && FILE_VALUE_DATETIME == right)
             || (FILE_VALUE_DATETIME == left && FILE_VALUE_DATE == right)) {
    type = FILE_VALUE_DATETIME;
  }
  return type;
}

common::ObObjType ObFileValueParser::to_obj_type(const ObFileValueType type)
{
  common::ObObjType obj_type = ObVarcharType;
  switch (type) {
  case FILE_VALUE_BOOLEAN:
    obj_type = ObTinyIntType;
    break;
  case FILE_VALUE_BIGINT:
    obj_type = ObIntType;
    break;
  case FILE_VALUE_DOUBLE:
    obj_type = ObDoubleType;
    break;
  case FILE_VALUE_DATE:
    obj_type = ObDateType;
    break;
  case FILE_VALUE_DATETIME:
    obj_type = ObDateTimeType;
    break;
  default:
    break;
  }
  return obj_type;
}

const char *ObFileValueParser::type_name(const ObFileValueType type)
{
  const char *name = "VARCHAR";
  switch (type) {
  case FILE_VALUE_BOOLEAN:
    name = "BOOLEAN";
    break;
  case FILE_VALUE_BIGINT:
    name = "BIGINT";
    break;
  case FILE_VALUE_DOUBLE:
    name = "DOUBLE";
    break;
  case FILE_VALUE_DATE:
    name = "DATE";
    break;
  case FILE_VALUE_DATETIME:
    name = "DATETIME";
    break;
  default:
    break;
  }
  return name;
}

int ObFileScanUtils::infer_csv_column_types(common::ObIAllocator &alloc,
                                            const common::ObString &real_path,
                                            const ObCsvScanOptions &options,
                                            const bool with_header,
                                            const int64_t column_count,
                                            common::ObIArray<ObFileColumnSchema> &schema)
{
  int ret = OB_SUCCESS;
  ObFileInput input;
  ObCsvScanner scanner;
  common::ObSEArray<ObFileScanColumnDef, 16> columns;
  common::ObSEArray<common::ObString, 16> row;
  schema.reuse();
  if (real_path.empty() || column_count <= 0) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid csv schema argument", K(ret), K(real_path), K(column_count));
  } else if (OB_FAIL(check_column_count(column_count))) {
    LOG_WARN("too many columns to sample", K(ret), K(column_count));
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < column_count; ++i) {
    ObFileScanColumnDef def;
    def.meta_.set_type(ObVarcharType);
    def.meta_.set_collation_type(CS_TYPE_UTF8MB4_GENERAL_CI);
    def.is_nullable_ = true;
    ObFileColumnSchema one;
    if (OB_FAIL(columns.push_back(def))) {
      LOG_WARN("failed to push sampled column", K(ret), K(i));
    } else if (OB_FAIL(schema.push_back(one))) {
      LOG_WARN("failed to push schema entry", K(ret), K(i));
    }
  }
  if (OB_FAIL(ret)) {
  } else if (OB_FAIL(input.open(alloc, real_path))) {
    LOG_WARN("failed to open file for sampling", K(ret), K(real_path));
  } else {
    scanner.set_with_header(with_header);
    scanner.set_options(options);
    if (OB_FAIL(scanner.open(input, columns))) {
      LOG_WARN("failed to open csv scanner for sampling", K(ret), K(real_path));
    } else {
      bool done = false;
      while (OB_SUCC(ret) && !done) {
        row.reuse();
        if (OB_FAIL(scanner.next_row(row))) {
          if (OB_ITER_END == ret) {
            ret = OB_SUCCESS;
            done = true;
          } else {
            LOG_WARN("failed to sample csv record", K(ret), K(real_path),
                     "error_pos", scanner.get_last_error_pos());
          }
        } else {
          for (int64_t i = 0; i < row.count() && i < schema.count(); ++i) {
            const common::ObString &text = row.at(i);
            ObFileColumnSchema &one = schema.at(i);
            if (OB_ISNULL(text.ptr())) {
              one.nullable_ = true;
            } else {
              const ObFileValueType type = ObFileValueParser::recognize(text);
              if (FILE_VALUE_DATETIME == type) {
                int64_t value = 0;
                int8_t scale = 0;
                if (ObFileValueParser::parse_datetime(text, value, scale) && scale > one.scale_) {
                  one.scale_ = scale;
                }
              }
              one.type_ = ObFileValueParser::merge(one.type_, type);
            }
          }
        }
      }
    }
    scanner.close();
    input.close();
  }
  // a column that never held a value is a nullable string, and only a datetime
  // column keeps a fractional seconds scale
  for (int64_t i = 0; OB_SUCC(ret) && i < schema.count(); ++i) {
    if (FILE_VALUE_UNKNOWN == schema.at(i).type_) {
      schema.at(i).type_ = FILE_VALUE_VARCHAR;
      schema.at(i).nullable_ = true;
    }
    if (FILE_VALUE_DATETIME != schema.at(i).type_) {
      schema.at(i).scale_ = 0;
    }
  }
  return ret;
}

// Reports a malformed record to the client. The position travels inside the
// message: the line/column fields of the warning buffer describe the SQL
// statement, not the file being read, so they cannot be reused here.
static void compose_csv_error_msg(char *buf,
                                  const int64_t buf_len,
                                  const char *what,
                                  const int64_t line,
                                  const int64_t column,
                                  const int64_t byte_offset)
{
  const int written = ::snprintf(buf, buf_len, "%s at line %ld, column %ld, byte offset %ld",
                                 what, line, column, byte_offset);
  if (written < 0 || written >= buf_len) {
    (void)::snprintf(buf, buf_len, "%s", what);
  }
}

ObCsvScanner::ObCsvScanner()
  : input_(NULL),
    columns_(NULL),
    record_buf_(),
    fields_(),
    options_(),
    state_(FIELD_BEGIN),
    cur_off_(0),
    with_header_(true),
    header_done_(false),
    has_content_(false),
    escape_pending_(false),
    line_(1),
    line_start_off_(0),
    rec_start_line_(1),
    rec_start_off_(0)
{
}

ObCsvScanner::~ObCsvScanner()
{
  close();
}

int ObCsvScanner::open(ObFileInput &input, const common::ObIArray<ObFileScanColumnDef> &columns)
{
  int ret = OB_SUCCESS;
  state_ = FIELD_BEGIN;
  cur_off_ = 0;
  header_done_ = false;
  has_content_ = false;
  escape_pending_ = false;
  line_ = 1;
  line_start_off_ = 0;
  rec_start_line_ = 1;
  rec_start_off_ = 0;
  record_buf_.reuse();
  fields_.reuse();
  input_ = &input;
  columns_ = &columns;
  last_err_pos_.reset();
  return ret;
}

void ObCsvScanner::close()
{
  input_ = NULL;
  columns_ = NULL;
  record_buf_.reuse();
  fields_.reuse();
}

int ObCsvScanner::rescan()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("csv scanner is not opened", K(ret));
  } else if (OB_FAIL(input_->seek_begin())) {
    LOG_WARN("failed to rewind csv file", K(ret));
  } else {
    state_ = FIELD_BEGIN;
    cur_off_ = 0;
    header_done_ = false;
    has_content_ = false;
    escape_pending_ = false;
    line_ = 1;
    line_start_off_ = 0;
    rec_start_line_ = 1;
    rec_start_off_ = 0;
    record_buf_.reuse();
    fields_.reuse();
    last_err_pos_.reset();
  }
  return ret;
}

// Every malformed record is a 1210 whose text carries the position in the file.
int ObCsvScanner::structural_error(const char *what,
                                   const int64_t line,
                                   const int64_t column,
                                   const int64_t byte_offset)
{
  const int ret = OB_INVALID_ARGUMENT;
  last_err_pos_.line_ = line;
  last_err_pos_.column_ = column;
  last_err_pos_.byte_offset_ = byte_offset;
  char msg[192] = { 0 };
  compose_csv_error_msg(msg, sizeof(msg), what, line, column, byte_offset);
  LOG_USER_ERROR(OB_INVALID_ARGUMENT, msg);
  LOG_WARN("invalid csv record", K(ret), K(what), K(last_err_pos_));
  return ret;
}

int ObCsvScanner::start_field()
{
  cur_off_ = record_buf_.length();
  has_content_ = true;
  return OB_SUCCESS;
}

int ObCsvScanner::append_record(const char *data, const int64_t len)
{
  int ret = OB_SUCCESS;
  if (len <= 0) {
    // nothing to do
  } else if (record_buf_.length() + len > ObFileScanLimits::MAX_RECORD_LENGTH) {
    ret = OB_SIZE_OVERFLOW;
    last_err_pos_.line_ = line_;
    last_err_pos_.byte_offset_ = OB_ISNULL(input_) ? 0 : input_->logical_pos();
    LOG_WARN("csv record is too long", K(ret), "length", record_buf_.length() + len,
             K(last_err_pos_), "limit", ObFileScanLimits::MAX_RECORD_LENGTH);
  } else if (OB_FAIL(record_buf_.append(data, len))) {
    LOG_WARN("failed to append to record buffer", K(ret), K(len));
  } else {
    has_content_ = true;
  }
  return ret;
}

int ObCsvScanner::finish_field(const bool quoted)
{
  int ret = OB_SUCCESS;
  Field field;
  field.off_ = cur_off_;
  field.len_ = record_buf_.length() - cur_off_;
  // an unquoted empty field carries no value at all, and neither does one that
  // reads exactly as the configured null marker; a quoted field is always text
  bool is_null = !quoted && field.len_ <= 0;
  if (!is_null && !quoted && options_.has_nullstr_
      && field.len_ == options_.nullstr_.length()
      && NULL != record_buf_.ptr()
      && 0 == MEMCMP(record_buf_.ptr() + cur_off_, options_.nullstr_.ptr(), field.len_)) {
    is_null = true;
  }
  field.is_null_ = is_null;
  if (field.len_ > ObFileScanLimits::MAX_FIELD_LENGTH) {
    ret = OB_SIZE_OVERFLOW;
    last_err_pos_.line_ = line_;
    last_err_pos_.byte_offset_ = OB_ISNULL(input_) ? 0 : input_->logical_pos();
    LOG_WARN("csv field is too long", K(ret), K(field), K(last_err_pos_),
             "limit", ObFileScanLimits::MAX_FIELD_LENGTH);
  } else if (OB_FAIL(fields_.push_back(field))) {
    LOG_WARN("failed to push csv field", K(ret), K(field));
  } else {
    has_content_ = true;
    cur_off_ = record_buf_.length();
  }
  return ret;
}

int ObCsvScanner::parse_one_record()
{
  int ret = OB_SUCCESS;
  bool end_of_record = false;
  bool hit_eof = false;
  bool rec_start_saved = false;
  record_buf_.reuse();
  fields_.reuse();
  cur_off_ = 0;
  has_content_ = false;
  while (OB_SUCC(ret) && !end_of_record && !hit_eof) {
    const common::ObString window = input_->buffered();
    if (window.empty()) {
      if (OB_FAIL(input_->fill())) {
        if (OB_ITER_END == ret) {
          ret = OB_SUCCESS;
          hit_eof = true;
        } else {
          LOG_WARN("failed to fill csv read window", K(ret));
        }
      }
    } else {
      const int64_t base = input_->logical_pos();
      const char *data = window.ptr();
      const int64_t len = window.length();
      int64_t i = 0;
      while (OB_SUCC(ret) && i < len && !end_of_record) {
        const char c = data[i];
        const int64_t byte_offset = base + i;
        if (AFTER_CR == state_) {
          state_ = FIELD_BEGIN;
          if ('\n' == c) {
            line_start_off_ = byte_offset + 1;
            ++i;
            continue;
          }
        }
        if (!rec_start_saved) {
          // remember where this record begins: a structural error is only
          // noticed after the record has been consumed
          rec_start_saved = true;
          rec_start_line_ = line_;
          rec_start_off_ = byte_offset;
        }
        switch (state_) {
        case FIELD_BEGIN:
          if (options_.delimiter_ == c) {
            if (OB_FAIL(finish_field(false))) {
            } else {
              ++i;
            }
            continue;
          } else if ('\n' == c) {
            end_of_record = true;
            ++line_;
            line_start_off_ = byte_offset + 1;
          } else if ('\r' == c) {
            end_of_record = true;
            state_ = AFTER_CR;
            ++line_;
            line_start_off_ = byte_offset + 1;
          } else if (options_.quote_ == c) {
            (void)start_field();
            state_ = IN_QUOTED;
          } else {
            (void)start_field();
            if (OB_FAIL(append_record(&c, 1))) {
            } else {
              state_ = IN_PLAIN;
            }
          }
          break;
        case IN_PLAIN:
          if (options_.delimiter_ == c) {
            if (OB_FAIL(finish_field(false))) {
            } else {
              state_ = FIELD_BEGIN;
            }
          } else if ('\n' == c) {
            if (OB_FAIL(finish_field(false))) {
            } else {
              end_of_record = true;
              state_ = FIELD_BEGIN;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if ('\r' == c) {
            if (OB_FAIL(finish_field(false))) {
            } else {
              end_of_record = true;
              state_ = AFTER_CR;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if (OB_FAIL(append_record(&c, 1))) {
            LOG_WARN("failed to append csv field", K(ret), K(byte_offset));
          }
          break;
        case IN_QUOTED:
          if (escape_pending_) {
            if (OB_FAIL(append_record(&c, 1))) {
              LOG_WARN("failed to append escaped csv byte", K(ret), K(byte_offset));
            } else {
              escape_pending_ = false;
              if ('\n' == c) {
                ++line_;
                line_start_off_ = byte_offset + 1;
              }
            }
          } else if (options_.quote_ == c) {
            state_ = QUOTE_IN_QUOTED;
          } else if (options_.escape_ != options_.quote_ && options_.escape_ == c) {
            escape_pending_ = true;
          } else if (OB_FAIL(append_record(&c, 1))) {
            LOG_WARN("failed to append quoted csv field", K(ret), K(byte_offset));
          } else if ('\n' == c) {
            ++line_;
            line_start_off_ = byte_offset + 1;
          }
          break;
        case QUOTE_IN_QUOTED:
          if (options_.quote_ == c) {
            if (OB_FAIL(append_record(&c, 1))) {
            } else {
              state_ = IN_QUOTED;
            }
          } else if (options_.delimiter_ == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              state_ = FIELD_BEGIN;
            }
          } else if ('\n' == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              end_of_record = true;
              state_ = FIELD_BEGIN;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if ('\r' == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              end_of_record = true;
              state_ = AFTER_CR;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if (' ' == c || '\t' == c) {
            state_ = AFTER_QUOTE;
          } else {
            // only a delimiter, a line end or another quote may follow a
            // closing quote; anything else means the record is malformed
            ret = structural_error("csv field has unexpected text after the closing quote",
                                   line_, fields_.count() + 1, byte_offset);
          }
          break;
        case AFTER_QUOTE:
          if (options_.delimiter_ == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              state_ = FIELD_BEGIN;
            }
          } else if ('\n' == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              end_of_record = true;
              state_ = FIELD_BEGIN;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if ('\r' == c) {
            if (OB_FAIL(finish_field(true))) {
            } else {
              end_of_record = true;
              state_ = AFTER_CR;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if (' ' != c && '\t' != c) {
            ret = structural_error("csv field has unexpected text after the closing quote",
                                   line_, fields_.count() + 1, byte_offset);
          }
          break;
        case AFTER_CR:
          // handled above, never reached here
          ret = OB_ERR_UNEXPECTED;
          LOG_WARN("unexpected csv state", K(ret), K(byte_offset));
          break;
        default:
          ret = OB_ERR_UNEXPECTED;
          LOG_WARN("unexpected csv state", K(ret), "state", static_cast<int>(state_));
          break;
        }
        if (OB_SUCC(ret)) {
          last_err_pos_.byte_offset_ = base + i;
          last_err_pos_.line_ = line_;
          ++i;
        }
      }
      input_->consume(i);
    }
  }
  if (OB_SUCC(ret) && hit_eof) {
    // the last record of the file may have no terminator
    if (IN_PLAIN == state_ || QUOTE_IN_QUOTED == state_ || AFTER_QUOTE == state_) {
      if (OB_FAIL(finish_field(QUOTE_IN_QUOTED == state_ || AFTER_QUOTE == state_))) {
      } else {
        state_ = FIELD_BEGIN;
      }
    } else if (IN_QUOTED == state_) {
      ret = structural_error("csv field has no closing quote",
                             line_, fields_.count() + 1, rec_start_off_ + cur_off_);
    }
    if (OB_SUCC(ret) && 0 == fields_.count()) {
      ret = OB_ITER_END;
    }
  }
  return ret;
}

int ObCsvScanner::next_record()
{
  int ret = OB_SUCCESS;
  bool emitted = false;
  if (OB_ISNULL(input_) || OB_ISNULL(columns_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("csv scanner is not opened", K(ret));
  } else {
    while (OB_SUCC(ret) && !emitted) {
      if (OB_FAIL(parse_one_record())) {
        if (OB_ITER_END != ret) {
          LOG_WARN("failed to parse csv record", K(ret), K(last_err_pos_));
        }
      } else if (0 == fields_.count()) {
        // a blank line holds no field at all, so it is not a record
      } else if (with_header_ && !header_done_) {
        header_done_ = true;
      } else {
        emitted = true;
      }
    }
  }
  return ret;
}

int ObCsvScanner::next_row(common::ObIArray<common::ObString> &row)
{
  int ret = OB_SUCCESS;
  static const char *empty_field = "";
  if (OB_FAIL(next_record())) {
    if (OB_ITER_END != ret) {
      LOG_WARN("failed to read csv record", K(ret));
    }
  } else {
    const int64_t column_cnt = columns_->count();
    if (column_cnt > 0 && fields_.count() > column_cnt) {
      ret = structural_error("csv record has more fields than columns",
                             rec_start_line_, column_cnt + 1,
                             rec_start_off_ + fields_.at(column_cnt).off_);
    } else if (column_cnt > 0 && fields_.count() < column_cnt) {
      ret = structural_error("csv record has fewer fields than columns",
                             rec_start_line_, fields_.count() + 1,
                             rec_start_off_ + record_buf_.length());
    }
    for (int64_t i = 0; OB_SUCC(ret) && i < fields_.count(); ++i) {
      const Field &field = fields_.at(i);
      common::ObString value;
      if (field.is_null_) {
        value.reset();
      } else if (0 == field.len_) {
        value = common::ObString(0, empty_field);
      } else {
        value = common::ObString(field.len_, const_cast<char *>(record_buf_.ptr() + field.off_));
      }
      if (OB_FAIL(row.push_back(value))) {
        LOG_WARN("failed to push csv field", K(ret), K(field));
      }
    }
  }
  return ret;
}

ObFileInput::ObFileInput()
  : fd_(-1),
    file_path_(),
    buf_(NULL),
    path_buf_(NULL),
    buf_alloc_(0),
    data_len_(0),
    pos_(0),
    read_off_(0),
    size_(0),
    mtime_(0),
    dev_(0),
    ino_(0),
    eof_(false),
    bom_skipped_(false),
    alloc_(NULL)
{
}

ObFileInput::~ObFileInput()
{
  close();
}

int ObFileInput::open(common::ObIAllocator &alloc, const common::ObString &real_path)
{
  int ret = OB_SUCCESS;
  close();
  if (real_path.empty() || real_path.length() >= PATH_MAX) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid resolved path", K(ret), K(real_path));
  } else if (OB_ISNULL(buf_ = static_cast<char *>(alloc.alloc(ObFileScanLimits::READ_BUF_SIZE)))) {
    ret = OB_ALLOCATE_MEMORY_FAILED;
    LOG_WARN("failed to alloc read buffer", K(ret), K(ObFileScanLimits::READ_BUF_SIZE));
  } else if (OB_ISNULL(path_buf_ = static_cast<char *>(alloc.alloc(real_path.length() + 1)))) {
    ret = OB_ALLOCATE_MEMORY_FAILED;
    LOG_WARN("failed to alloc path buffer", K(ret), K(real_path.length()));
  } else {
    alloc_ = &alloc;
    buf_alloc_ = ObFileScanLimits::READ_BUF_SIZE;
    MEMCPY(path_buf_, real_path.ptr(), real_path.length());
    path_buf_[real_path.length()] = '\0';
    file_path_.assign_ptr(path_buf_, real_path.length());
    char cstyle[PATH_MAX];
    struct stat stat_result;
    MEMCPY(cstyle, real_path.ptr(), real_path.length());
    cstyle[real_path.length()] = '\0';
    int fd = ::open(cstyle, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
      ret = OB_FILE_NOT_EXIST;
      LOG_WARN("failed to open file", K(ret), K(file_path_), "errno", errno);
    } else if (0 != ::fstat(fd, &stat_result) || !S_ISREG(stat_result.st_mode)) {
      ret = OB_INVALID_ARGUMENT;
      LOG_WARN("not a regular file", K(ret), K(file_path_), "errno", errno);
      ::close(fd);
    } else {
      fd_ = fd;
      dev_ = stat_result.st_dev;
      ino_ = stat_result.st_ino;
      size_ = stat_result.st_size;
      mtime_ = stat_result.st_mtime;
    }
  }
  if (OB_FAIL(ret)) {
    close();
  }
  return ret;
}

void ObFileInput::close()
{
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  if (OB_NOT_NULL(alloc_)) {
    if (OB_NOT_NULL(buf_)) {
      alloc_->free(buf_);
    }
    if (OB_NOT_NULL(path_buf_)) {
      alloc_->free(path_buf_);
    }
    alloc_ = NULL;
  }
  buf_ = NULL;
  path_buf_ = NULL;
  file_path_.reset();
  buf_alloc_ = 0;
  data_len_ = 0;
  pos_ = 0;
  read_off_ = 0;
  size_ = 0;
  mtime_ = 0;
  dev_ = 0;
  ino_ = 0;
  eof_ = false;
  bom_skipped_ = false;
}

int ObFileInput::fill()
{
  int ret = OB_SUCCESS;
  if (!is_opened()) {
    ret = OB_NOT_INIT;
    LOG_WARN("file input is not opened", K(ret));
  } else {
    const int64_t remain = data_len_ - pos_;
    if (remain > 0) {
      MEMMOVE(buf_, buf_ + pos_, remain);
    }
    data_len_ = remain;
    pos_ = 0;
    while (OB_SUCC(ret) && !eof_ && data_len_ < buf_alloc_) {
      const ssize_t n = ::read(fd_, buf_ + data_len_, buf_alloc_ - data_len_);
      if (n < 0) {
        if (EINTR == errno) {
          continue;
        }
        ret = OB_IO_ERROR;
        LOG_WARN("failed to read file", K(ret), K(file_path_), "errno", errno);
      } else if (0 == n) {
        eof_ = true;
      } else {
        data_len_ += n;
        read_off_ += n;
      }
    }
    if (OB_SUCC(ret) && !bom_skipped_) {
      bom_skipped_ = true;
      if (data_len_ >= 3 && 0 == MEMCMP(buf_, "\xEF\xBB\xBF", 3)) {
        // a UTF-8 BOM is encoding metadata, it is not part of the first value
        pos_ += 3;
      }
    }
    if (OB_SUCC(ret) && 0 == data_len_) {
      ret = OB_ITER_END;
    }
  }
  return ret;
}

int ObFileInput::check_fingerprint() const
{
  int ret = OB_SUCCESS;
  struct stat stat_result;
  if (0 != ::fstat(fd_, &stat_result)) {
    ret = OB_IO_ERROR;
    LOG_WARN("failed to stat opened file", K(ret), K(file_path_), "errno", errno);
  } else if (stat_result.st_dev != dev_
             || stat_result.st_ino != ino_
             || stat_result.st_size != size_
             || stat_result.st_mtime != mtime_) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("file changed after it was opened", K(ret), K(file_path_),
             "old_size", size_, "new_size", stat_result.st_size);
  }
  return ret;
}

int ObFileInput::seek_begin()
{
  int ret = OB_SUCCESS;
  if (!is_opened()) {
    ret = OB_NOT_INIT;
    LOG_WARN("file input is not opened", K(ret));
  } else if (OB_FAIL(check_fingerprint())) {
    LOG_WARN("failed to rescan file", K(ret), K(file_path_));
  } else if (0 != ::lseek(fd_, 0, SEEK_SET)) {
    ret = OB_IO_ERROR;
    LOG_WARN("failed to rewind file", K(ret), K(file_path_), "errno", errno);
  } else {
    data_len_ = 0;
    pos_ = 0;
    read_off_ = 0;
    eof_ = false;
    bom_skipped_ = false;
  }
  return ret;
}

} // end namespace sql
} // end namespace oceanbase
