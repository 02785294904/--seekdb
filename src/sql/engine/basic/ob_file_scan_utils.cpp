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
#include <new>
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
            // a meta character asks for whatever files the pattern names, so a
            // match that turns out to be a directory, a link leading outside the
            // boundary or a file removed in the meantime is not a failure of the
            // query: it is one of the names that has no readable file behind it.
            // Anything else, an over long path or an allocation that did not fit,
            // is a real error and stops the expansion.
            const int check_ret = resolve_and_check_path(raw_match, secure_file_priv,
                                                         skip_priv_check, resolved_buf,
                                                         sizeof(resolved_buf), real_path);
            if (OB_FILE_NOT_EXIST == check_ret || OB_INVALID_ARGUMENT == check_ret
                || OB_ERR_NO_PRIVILEGE == check_ret) {
              LOG_TRACE("skip unreadable glob match", K(check_ret), K(raw_match));
            } else if (OB_FAIL(check_ret)) {
              LOG_WARN("failed to check matched file", K(check_ret), K(raw_match));
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
            // a delimiter at the end of a line asks for one more field, empty,
            // after everything the line already holds
            if (has_content_ && OB_FAIL(finish_field(false))) {
            } else {
              end_of_record = true;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
          } else if ('\r' == c) {
            if (has_content_ && OB_FAIL(finish_field(false))) {
            } else {
              end_of_record = true;
              state_ = AFTER_CR;
              ++line_;
              line_start_off_ = byte_offset + 1;
            }
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
    if (IN_PLAIN == state_ || QUOTE_IN_QUOTED == state_ || AFTER_QUOTE == state_
        || (FIELD_BEGIN == state_ && has_content_)) {
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

namespace
{
// A malformed JSON record is a 1210 whose text carries where in the file it
// happened, the same shape a malformed CSV record is reported with. A JSON
// record has no field numbering a column could mean, so only the line and the
// byte offset are quoted.
void compose_json_error_msg(char *buf,
                            const int64_t buf_len,
                            const char *what,
                            const int64_t line,
                            const int64_t byte_offset)
{
  const int written = ::snprintf(buf, buf_len, "%s at line %ld, byte offset %ld",
                                 what, line, byte_offset);
  if (written < 0 || written >= buf_len) {
    (void)::snprintf(buf, buf_len, "%s", what);
  }
}

inline bool is_json_space(const char c)
{
  return ' ' == c || '\t' == c || '\n' == c || '\r' == c;
}

inline bool is_json_hex_digit(const char c, int64_t &value)
{
  bool bool_ret = false;
  value = 0;
  if (c >= '0' && c <= '9') {
    value = c - '0';
    bool_ret = true;
  } else if (c >= 'a' && c <= 'f') {
    value = c - 'a' + 10;
    bool_ret = true;
  } else if (c >= 'A' && c <= 'F') {
    value = c - 'A' + 10;
    bool_ret = true;
  }
  return bool_ret;
}

// Whether a byte may stand inside a value that is not a string. Numbers and the
// three literals are collected this way and only judged at the end, so a value
// never gets one rule while being read and another while being converted.
inline bool is_json_value_char(const char c)
{
  return ('0' <= c && c <= '9') || '+' == c || '-' == c || '.' == c
      || 'e' == c || 'E' == c || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

// Keys are matched byte for byte: two keys that differ only in case name two
// different JSON members, whatever SQL makes of the two column names they get.
int compare_json_name(const common::ObString &left, const common::ObString &right)
{
  int compare_result = 0;
  if (left.length() != right.length()) {
    compare_result = left.length() < right.length() ? -1 : 1;
  } else if (0 == left.length()) {
    // two empty keys are the same key
  } else {
    compare_result = MEMCMP(left.ptr(), right.ptr(), left.length());
  }
  return compare_result;
}
} // end anonymous namespace

ObJsonlReader::ObJsonlReader()
  : input_(NULL),
    record_buf_(),
    members_(),
    state_(BEFORE_OBJECT),
    escape_(ESC_NONE),
    token_off_(0),
    hex_value_(0),
    hex_count_(0),
    high_part_(0),
    high_pending_(false),
    depth_(0),
    container_string_(false),
    container_escape_(false),
    line_(1),
    rec_start_line_(1),
    rec_start_off_(0),
    last_err_pos_()
{
}

ObJsonlReader::~ObJsonlReader()
{
  close();
}

int ObJsonlReader::open(ObFileInput &input)
{
  input_ = &input;
  reset_record();
  state_ = BEFORE_OBJECT;
  line_ = 1;
  last_err_pos_.reset();
  return OB_SUCCESS;
}

void ObJsonlReader::close()
{
  input_ = NULL;
  reset_record();
}

int ObJsonlReader::rescan()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("json reader is not opened", K(ret));
  } else if (OB_FAIL(input_->seek_begin())) {
    LOG_WARN("failed to rewind json file", K(ret));
  } else {
    reset_record();
    state_ = BEFORE_OBJECT;
    line_ = 1;
    last_err_pos_.reset();
  }
  return ret;
}

void ObJsonlReader::reset_record()
{
  record_buf_.reuse();
  members_.reuse();
  escape_ = ESC_NONE;
  token_off_ = 0;
  hex_value_ = 0;
  hex_count_ = 0;
  high_part_ = 0;
  high_pending_ = false;
  depth_ = 0;
  container_string_ = false;
  container_escape_ = false;
}

int ObJsonlReader::structural_error(const char *what, const int64_t byte_offset)
{
  const int ret = OB_INVALID_ARGUMENT;
  last_err_pos_.line_ = line_;
  last_err_pos_.column_ = 0;
  last_err_pos_.byte_offset_ = byte_offset;
  char msg[192] = { 0 };
  compose_json_error_msg(msg, sizeof(msg), what, line_, byte_offset);
  LOG_USER_ERROR(OB_INVALID_ARGUMENT, msg);
  LOG_WARN("invalid json record", K(ret), K(what), K(last_err_pos_));
  return ret;
}

int ObJsonlReader::push(const char c)
{
  int ret = OB_SUCCESS;
  if (record_buf_.length() + 1 > ObFileScanLimits::MAX_RECORD_LENGTH) {
    ret = OB_SIZE_OVERFLOW;
    last_err_pos_.line_ = line_;
    last_err_pos_.byte_offset_ = OB_ISNULL(input_) ? 0 : input_->logical_pos();
    LOG_WARN("json record is too long", K(ret), "length", record_buf_.length() + 1,
             K(last_err_pos_), "limit", ObFileScanLimits::MAX_RECORD_LENGTH);
  } else if (OB_FAIL(record_buf_.append(&c, 1))) {
    LOG_WARN("failed to append to json record buffer", K(ret));
  }
  return ret;
}

// One code point as UTF-8, which is what a text column holds.
int ObJsonlReader::push_code_point(const uint32_t code_point)
{
  int ret = OB_SUCCESS;
  char buf[4] = { 0 };
  int64_t len = 1;
  if (code_point < 0x80) {
    buf[0] = static_cast<char>(code_point);
  } else if (code_point < 0x800) {
    buf[0] = static_cast<char>(0xC0 | (code_point >> 6));
    buf[1] = static_cast<char>(0x80 | (code_point & 0x3F));
    len = 2;
  } else if (code_point < 0x10000) {
    buf[0] = static_cast<char>(0xE0 | (code_point >> 12));
    buf[1] = static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
    buf[2] = static_cast<char>(0x80 | (code_point & 0x3F));
    len = 3;
  } else {
    buf[0] = static_cast<char>(0xF0 | (code_point >> 18));
    buf[1] = static_cast<char>(0x80 | ((code_point >> 12) & 0x3F));
    buf[2] = static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
    buf[3] = static_cast<char>(0x80 | (code_point & 0x3F));
    len = 4;
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < len; ++i) {
    if (OB_FAIL(push(buf[i]))) {
      LOG_WARN("failed to append escaped json character", K(ret), K(code_point));
    }
  }
  return ret;
}

// The token that has just been read belongs to the record: a name opens a new
// member, a value closes the one the name opened.
int ObJsonlReader::finish_token(const bool is_name)
{
  int ret = OB_SUCCESS;
  escape_ = ESC_NONE;
  high_pending_ = false;
  const int64_t len = record_buf_.length() - token_off_;
  if (is_name) {
    ObJsonlMember member;
    member.key_off_ = token_off_;
    member.key_len_ = len;
    if (OB_FAIL(members_.push_back(member))) {
      LOG_WARN("failed to push json member", K(ret), K(token_off_), K(len));
    } else {
      state_ = BEFORE_COLON;
    }
  } else if (members_.empty()) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("json value has no member name", K(ret), K(token_off_), K(len));
  } else {
    ObJsonlMember &member = members_.at(members_.count() - 1);
    member.value_off_ = token_off_;
    member.value_len_ = len;
    member.is_null_ = false;
    // only a quoted token can reach here, and what the file put in quotes is a
    // string whatever its characters look like
    member.is_string_ = true;
    state_ = AFTER_VALUE;
  }
  return ret;
}

// A number, true, false or null ends at the first byte that cannot be part of
// it, and that byte still has to be looked at in the state after the value.
int ObJsonlReader::finish_plain_value(const int64_t byte_offset)
{
  int ret = OB_SUCCESS;
  // The buffer is only looked at here, while its address is still the one the
  // token was written into; what the member keeps is the offset.
  const int64_t len = record_buf_.length() - token_off_;
  const char *text = (len > 0) ? record_buf_.ptr() + token_off_ : NULL;
  bool known = true;
  if (NULL == text) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("empty json value token", K(ret), K(byte_offset));
  } else {
    const char first = text[0];
    if ((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
      // a value that starts with a letter is one of the three literals, nothing else
      if (4 == len && 0 == MEMCMP(text, "null", 4)) {
        members_.at(members_.count() - 1).is_null_ = true;
      } else if (!((4 == len && 0 == MEMCMP(text, "true", 4))
                   || (5 == len && 0 == MEMCMP(text, "false", 5)))) {
        known = false;
      }
    }
  }
  if (OB_FAIL(ret)) {
  } else if (!known) {
    ret = structural_error("json value is neither a number nor a literal", byte_offset);
  } else {
    ObJsonlMember &member = members_.at(members_.count() - 1);
    member.value_off_ = token_off_;
    member.value_len_ = len;
    state_ = AFTER_VALUE;
  }
  return ret;
}

// Everything up to the closing quote of a name or of a string value, with the
// escapes decoded into the record buffer.
int ObJsonlReader::step_string(const char c,
                               const int64_t byte_offset,
                               const bool is_name)
{
  int ret = OB_SUCCESS;
  switch (escape_) {
  case ESC_NONE:
    if ('"' == c) {
      if (high_pending_) {
        ret = structural_error("json string ends on an unpaired surrogate", byte_offset);
      } else if (OB_FAIL(finish_token(is_name))) {
        LOG_WARN("failed to close json token", K(ret), K(is_name));
      }
    } else if ('\\' == c) {
      escape_ = ESC_CHAR;
    } else if (OB_FAIL(push(c))) {
      LOG_WARN("failed to append json string character", K(ret), K(c));
    }
    break;
  case ESC_CHAR:
    switch (c) {
    case 'b':
      escape_ = ESC_NONE;
      ret = push('\b');
      break;
    case 'f':
      escape_ = ESC_NONE;
      ret = push('\f');
      break;
    case 'n':
      escape_ = ESC_NONE;
      ret = push('\n');
      break;
    case 'r':
      escape_ = ESC_NONE;
      ret = push('\r');
      break;
    case 't':
      escape_ = ESC_NONE;
      ret = push('\t');
      break;
    case '"':
    case '\\':
    case '/':
      escape_ = ESC_NONE;
      ret = push(c);
      break;
    case 'u':
      escape_ = ESC_DIGITS;
      hex_value_ = 0;
      hex_count_ = 0;
      break;
    default:
      ret = structural_error("json string has an unknown escape", byte_offset);
      break;
    }
    break;
  case ESC_DIGITS: {
    int64_t digit = 0;
    if (!is_json_hex_digit(c, digit)) {
      ret = structural_error("json string has an incomplete unicode escape", byte_offset);
    } else if (FALSE_IT(hex_value_ = hex_value_ * 16 + digit)) {
    } else if (++hex_count_ < 4) {
      // more digits to come
    } else if (high_pending_) {
      if (hex_value_ < 0xDC00 || hex_value_ > 0xDFFF) {
        ret = structural_error("json string has an unpaired surrogate", byte_offset);
      } else {
        const uint32_t combined = 0x10000u
            + ((static_cast<uint32_t>(high_part_) - 0xD800u) << 10)
            + (static_cast<uint32_t>(hex_value_) - 0xDC00u);
        high_pending_ = false;
        escape_ = ESC_NONE;
        ret = push_code_point(combined);
      }
    } else if (hex_value_ >= 0xD800 && hex_value_ <= 0xDBFF) {
      high_part_ = static_cast<uint32_t>(hex_value_);
      high_pending_ = true;
      escape_ = ESC_NONE;
    } else if (hex_value_ >= 0xDC00 && hex_value_ <= 0xDFFF) {
      ret = structural_error("json string has an unpaired surrogate", byte_offset);
    } else {
      escape_ = ESC_NONE;
      ret = push_code_point(static_cast<uint32_t>(hex_value_));
    }
    break;
  }
  default:
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("unexpected json escape state", K(ret), "escape", static_cast<int>(escape_));
    break;
  }
  return ret;
}

// A nested value is not interpreted; it is kept as the bytes the file holds, so
// that it travels into a text column unchanged. Only the nesting and the quoted
// strings inside it have to be understood to know where it ends.
int ObJsonlReader::step_container(const char c)
{
  int ret = OB_SUCCESS;
  if (OB_FAIL(push(c))) {
    LOG_WARN("failed to append json container byte", K(ret), K(c));
  } else if (container_escape_) {
    container_escape_ = false;
  } else if (container_string_) {
    if ('\\' == c) {
      container_escape_ = true;
    } else if ('"' == c) {
      container_string_ = false;
    }
  } else if ('"' == c) {
    container_string_ = true;
  } else if ('{' == c || '[' == c) {
    ++depth_;
  } else if ('}' == c || ']' == c) {
    --depth_;
    if (depth_ <= 0) {
      if (members_.empty()) {
        ret = OB_ERR_UNEXPECTED;
        LOG_WARN("json container has no member name", K(ret));
      } else {
        ObJsonlMember &member = members_.at(members_.count() - 1);
        member.value_off_ = token_off_;
        member.value_len_ = record_buf_.length() - token_off_;
        member.is_null_ = false;
        state_ = AFTER_VALUE;
      }
    }
  }
  return ret;
}

int ObJsonlReader::step(const char c,
                        const int64_t byte_offset,
                        bool &record_done,
                        bool &retry)
{
  int ret = OB_SUCCESS;
  const bool space = is_json_space(c);
  switch (state_) {
  case BEFORE_OBJECT:
    if (space) {
      // whitespace between two records carries no value
    } else if ('{' == c) {
      rec_start_line_ = line_;
      rec_start_off_ = byte_offset;
      // the opening brace is the record itself, the name machine starts behind it
      state_ = BEFORE_NAME;
    } else {
      ret = structural_error("file record is not a JSON object", byte_offset);
    }
    break;
  case BEFORE_NAME:
    if (space) {
    } else if ('"' == c) {
      token_off_ = record_buf_.length();
      escape_ = ESC_NONE;
      high_pending_ = false;
      state_ = IN_NAME;
    } else if ('}' == c) {
      record_done = true;
    } else if (':' == c || ',' == c) {
      ret = structural_error("json object member has no name", byte_offset);
    } else {
      ret = structural_error("json object member name is not a string", byte_offset);
    }
    break;
  case IN_NAME:
    ret = step_string(c, byte_offset, true);
    break;
  case BEFORE_COLON:
    if (space) {
    } else if (':' == c) {
      state_ = BEFORE_VALUE;
    } else {
      ret = structural_error("json object member has no colon", byte_offset);
    }
    break;
  case BEFORE_VALUE:
    if (space) {
    } else if ('"' == c) {
      token_off_ = record_buf_.length();
      escape_ = ESC_NONE;
      high_pending_ = false;
      state_ = IN_STRING_VALUE;
    } else if ('{' == c || '[' == c) {
      token_off_ = record_buf_.length();
      depth_ = 1;
      container_string_ = false;
      container_escape_ = false;
      if (OB_FAIL(push(c))) {
        LOG_WARN("failed to start json container value", K(ret), K(c));
      } else {
        state_ = IN_CONTAINER;
      }
    } else if (is_json_value_char(c)) {
      token_off_ = record_buf_.length();
      if (OB_FAIL(push(c))) {
        LOG_WARN("failed to start json value", K(ret), K(c));
      } else {
        state_ = IN_PLAIN_VALUE;
      }
    } else {
      ret = structural_error("json object member has no value", byte_offset);
    }
    break;
  case IN_STRING_VALUE:
    ret = step_string(c, byte_offset, false);
    break;
  case IN_PLAIN_VALUE:
    if (is_json_value_char(c)) {
      if (OB_FAIL(push(c))) {
        LOG_WARN("failed to append json value character", K(ret), K(c));
      }
    } else if (OB_FAIL(finish_plain_value(byte_offset))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to close json value", K(ret), K(byte_offset));
      }
    } else {
      // the byte that ended the value belongs to the state after it
      retry = true;
    }
    break;
  case IN_CONTAINER:
    ret = step_container(c);
    break;
  case AFTER_VALUE:
    if (space) {
    } else if (',' == c) {
      state_ = BEFORE_NAME;
    } else if ('}' == c) {
      record_done = true;
    } else {
      ret = structural_error("json object has unexpected text in it", byte_offset);
    }
    break;
  default:
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("unexpected json state", K(ret), "state", static_cast<int>(state_));
    break;
  }
  return ret;
}

int ObJsonlReader::next_object(common::ObIArray<ObJsonlMember> &members)
{
  int ret = OB_SUCCESS;
  members.reuse();
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("json reader is not opened", K(ret));
  } else {
    // The record handed out last shares this buffer with the caller, so it is
    // cleared here rather than when that record was returned.
    reset_record();
    bool record_done = false;
    bool hit_eof = false;
    while (OB_SUCC(ret) && !record_done && !hit_eof) {
      const common::ObString window = input_->buffered();
      if (window.empty()) {
        if (OB_FAIL(input_->fill())) {
          if (OB_ITER_END == ret) {
            ret = OB_SUCCESS;
            hit_eof = true;
          } else {
            LOG_WARN("failed to fill json read window", K(ret));
          }
        }
      } else {
        const int64_t base = input_->logical_pos();
        const char *data = window.ptr();
        const int64_t len = window.length();
        int64_t i = 0;
        while (OB_SUCC(ret) && i < len && !record_done) {
          const char c = data[i];
          const int64_t byte_offset = base + i;
          bool retry = false;
          ret = step(c, byte_offset, record_done, retry);
          if (OB_FAIL(ret)) {
            LOG_WARN("failed to parse json record", K(ret), K(byte_offset));
          } else if (!retry) {
            if ('\n' == c) {
              ++line_;
            }
            ++i;
          }
        }
        input_->consume(i);
      }
    }
    if (OB_FAIL(ret)) {
    } else if (record_done) {
      // The record is whole now, so its tokens can be pointed at: the buffer
      // holds still and will not move again before the next call.
      const char *base = record_buf_.ptr();
      for (int64_t i = 0; i < members_.count(); ++i) {
        ObJsonlMember &one = members_.at(i);
        if (one.key_off_ >= 0) {
          one.key_ = common::ObString(static_cast<int32_t>(one.key_len_),
                                      const_cast<char *>(base + one.key_off_));
        }
        if (one.value_off_ >= 0) {
          one.value_ = common::ObString(static_cast<int32_t>(one.value_len_),
                                        const_cast<char *>(base + one.value_off_));
        }
      }
      if (OB_FAIL(members.assign(members_))) {
        LOG_WARN("failed to copy json members", K(ret));
      } else {
        state_ = BEFORE_OBJECT;
      }
    } else if (BEFORE_OBJECT == state_) {
      // nothing but whitespace between the last record and the end of the file
      ret = OB_ITER_END;
    } else {
      line_ = rec_start_line_;
      ret = structural_error("json object is not complete", rec_start_off_);
    }
  }
  return ret;
}

int ObJsonlScanner::build_name_order(const common::ObIArray<common::ObString> &names,
                                     common::ObIArray<int64_t> &order)
{
  int ret = OB_SUCCESS;
  order.reuse();
  // The names are put in order as they are walked, which costs a search per
  // column once and leaves every later key lookup searching half the list.
  for (int64_t i = 0; OB_SUCC(ret) && i < names.count(); ++i) {
    int64_t low = 0;
    int64_t high = order.count();
    while (low < high) {
      const int64_t mid = low + (high - low) / 2;
      if (compare_json_name(names.at(order.at(mid)), names.at(i)) < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    if (OB_FAIL(order.push_back(0))) {
      LOG_WARN("failed to grow json name order", K(ret), K(i));
    } else {
      const int64_t count = order.count();
      for (int64_t j = count - 1; j > low; --j) {
        order.at(j) = order.at(j - 1);
      }
      order.at(low) = i;
    }
  }
  return ret;
}

int ObJsonlScanner::find_name(const common::ObIArray<common::ObString> &names,
                              const common::ObIArray<int64_t> &order,
                              const common::ObString &key,
                              int64_t &slot)
{
  int ret = OB_SUCCESS;
  slot = -1;
  int64_t low = 0;
  int64_t high = order.count() - 1;
  while (-1 == slot && low <= high) {
    const int64_t mid = low + (high - low) / 2;
    const int64_t name_idx = order.at(mid);
    const int compare_result = compare_json_name(key, names.at(name_idx));
    if (0 == compare_result) {
      slot = name_idx;
    } else if (compare_result < 0) {
      high = mid - 1;
    } else {
      low = mid + 1;
    }
  }
  return ret;
}

ObJsonlScanner::ObJsonlScanner()
  : input_(NULL), columns_(NULL), names_(), name_order_(), reader_()
{
}

ObJsonlScanner::~ObJsonlScanner()
{
  close();
}

int ObJsonlScanner::open(ObFileInput &input, const common::ObIArray<ObFileScanColumnDef> &columns)
{
  int ret = OB_SUCCESS;
  input_ = &input;
  columns_ = &columns;
  names_.reuse();
  name_order_.reuse();
  last_err_pos_.reset();
  for (int64_t i = 0; OB_SUCC(ret) && i < columns.count(); ++i) {
    if (OB_FAIL(names_.push_back(columns.at(i).column_name_))) {
      LOG_WARN("failed to collect json column name", K(ret), K(i));
    }
  }
  if (OB_FAIL(ret)) {
  } else if (OB_FAIL(build_name_order(names_, name_order_))) {
    LOG_WARN("failed to order json column names", K(ret));
  } else if (OB_FAIL(reader_.open(input))) {
    LOG_WARN("failed to open json reader", K(ret));
  }
  return ret;
}

void ObJsonlScanner::close()
{
  reader_.close();
  input_ = NULL;
  columns_ = NULL;
  names_.reuse();
  name_order_.reuse();
}

int ObJsonlScanner::rescan()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("json scanner is not opened", K(ret));
  } else if (OB_FAIL(reader_.rescan())) {
    LOG_WARN("failed to rewind json file", K(ret));
  } else {
    last_err_pos_.reset();
  }
  return ret;
}

int ObJsonlScanner::next_row(common::ObIArray<common::ObString> &row)
{
  int ret = OB_SUCCESS;
  common::ObSEArray<ObJsonlMember, 16> members;
  common::ObSEArray<common::ObString, 16> values;
  if (OB_FAIL(reader_.next_object(members))) {
    if (OB_ITER_END != ret) {
      LOG_WARN("failed to read json object", K(ret));
      last_err_pos_ = reader_.get_last_error_pos();
    }
  } else if (OB_ISNULL(columns_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("json scanner is not opened", K(ret));
  } else {
    const int64_t column_cnt = columns_->count();
    // a column no member names stays null, and a member no column is named for
    // is left out: the relation has no place to put it
    for (int64_t i = 0; OB_SUCC(ret) && i < column_cnt; ++i) {
      common::ObString absent;
      if (OB_FAIL(values.push_back(absent))) {
        LOG_WARN("failed to reserve json column", K(ret), K(i));
      }
    }
    for (int64_t i = 0; OB_SUCC(ret) && i < members.count(); ++i) {
      int64_t slot = -1;
      if (OB_FAIL(find_name(names_, name_order_, members.at(i).key_, slot))) {
        LOG_WARN("failed to match json member", K(ret), K(i));
      } else if (slot < 0 || members.at(i).is_null_) {
        // nothing to write: an unknown key or a null value both leave the slot null
      } else {
        values.at(slot) = members.at(i).value_;
      }
    }
    for (int64_t i = 0; OB_SUCC(ret) && i < column_cnt; ++i) {
      if (OB_FAIL(row.push_back(values.at(i)))) {
        LOG_WARN("failed to push json value", K(ret), K(i));
      }
    }
  }
  return ret;
}

int ObFileScanUtils::read_json_column_names(common::ObIAllocator &alloc,
                                            const common::ObString &real_path,
                                            common::ObIArray<common::ObString> &names)
{
  int ret = OB_SUCCESS;
  names.reuse();
  ObFileInput input;
  ObJsonlReader reader;
  common::ObSEArray<ObJsonlMember, 16> members;
  if (real_path.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid resolved path", K(ret), K(real_path));
  } else if (OB_FAIL(input.open(alloc, real_path))) {
    LOG_WARN("failed to open file for json keys", K(ret), K(real_path));
  } else if (OB_FAIL(reader.open(input))) {
    LOG_WARN("failed to open json reader", K(ret), K(real_path));
  } else {
    bool done = false;
    while (OB_SUCC(ret) && !done) {
      members.reuse();
      if (OB_FAIL(reader.next_object(members))) {
        if (OB_ITER_END == ret) {
          ret = OB_SUCCESS;
          done = true;
        } else {
          LOG_WARN("failed to read json object", K(ret), K(real_path),
                   "error_pos", reader.get_last_error_pos());
        }
      } else {
        for (int64_t i = 0; OB_SUCC(ret) && i < members.count(); ++i) {
          bool known = false;
          for (int64_t j = 0; !known && j < names.count(); ++j) {
            known = (0 == compare_json_name(names.at(j), members.at(i).key_));
          }
          common::ObString name;
          if (known) {
            // the key already names a column built by an earlier record
          } else if (OB_FAIL(ob_write_string(alloc, members.at(i).key_, name))) {
            LOG_WARN("failed to copy column name", K(ret), K(members.at(i)));
          } else if (OB_FAIL(names.push_back(name))) {
            LOG_WARN("failed to push column name", K(ret), K(name));
          }
        }
      }
    }
  }
  reader.close();
  input.close();
  return ret;
}

int ObFileScanUtils::infer_json_column_types(common::ObIAllocator &alloc,
                                             const common::ObString &real_path,
                                             const common::ObIArray<common::ObString> &names,
                                             common::ObIArray<ObFileColumnSchema> &schema)
{
  int ret = OB_SUCCESS;
  ObFileInput input;
  ObJsonlReader reader;
  common::ObSEArray<ObJsonlMember, 16> members;
  common::ObSEArray<int64_t, 16> name_order;
  common::ObSEArray<bool, 16> mentioned;
  schema.reuse();
  if (real_path.empty() || names.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid json schema argument", K(ret), K(real_path), "name_cnt",
             names.count());
  } else if (OB_FAIL(check_column_count(names.count()))) {
    LOG_WARN("too many columns to sample", K(ret), "column_cnt", names.count());
  } else if (OB_FAIL(ObJsonlScanner::build_name_order(names, name_order))) {
    LOG_WARN("failed to order json column names", K(ret), K(real_path));
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < names.count(); ++i) {
    ObFileColumnSchema one;
    if (OB_FAIL(schema.push_back(one))) {
      LOG_WARN("failed to push schema entry", K(ret), K(i));
    }
  }
  if (OB_FAIL(ret)) {
  } else if (OB_FAIL(input.open(alloc, real_path))) {
    LOG_WARN("failed to open file for json sampling", K(ret), K(real_path));
  } else if (OB_FAIL(reader.open(input))) {
    LOG_WARN("failed to open json reader for sampling", K(ret), K(real_path));
  } else {
    // The members are looked at as the reader left them rather than as a row,
    // because a value the file put in quotes is a string whatever it looks like,
    // and only the reader knows which values were quoted.
    bool done = false;
    while (OB_SUCC(ret) && !done) {
      members.reuse();
      mentioned.reuse();
      if (OB_FAIL(reader.next_object(members))) {
        if (OB_ITER_END == ret) {
          ret = OB_SUCCESS;
          done = true;
        } else {
          LOG_WARN("failed to sample json record", K(ret), K(real_path),
                   "error_pos", reader.get_last_error_pos());
        }
      }
      for (int64_t i = 0; OB_SUCC(ret) && !done && i < names.count(); ++i) {
        if (OB_FAIL(mentioned.push_back(false))) {
          LOG_WARN("failed to reserve sampled column", K(ret), K(i));
        }
      }
      for (int64_t i = 0; OB_SUCC(ret) && !done && i < members.count(); ++i) {
        int64_t slot = -1;
        if (OB_FAIL(ObJsonlScanner::find_name(names, name_order,
                                              members.at(i).key_, slot))) {
          LOG_WARN("failed to match sampled json member", K(ret), K(i));
        } else if (slot < 0) {
          // a key no column was built for cannot appear: the columns came from
          // this very file, but a record is not judged by that
        } else {
          mentioned.at(slot) = true;
          ObFileColumnSchema &one = schema.at(slot);
          if (members.at(i).is_null_) {
            one.nullable_ = true;
          } else {
            const common::ObString &text = members.at(i).value_;
            const ObFileValueType type = members.at(i).is_string_
                                         ? FILE_VALUE_VARCHAR
                                         : ObFileValueParser::recognize(text);
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
      // a record that does not mention a key leaves that column null this time
      for (int64_t i = 0; OB_SUCC(ret) && !done && i < mentioned.count()
           && i < schema.count(); ++i) {
        if (!mentioned.at(i)) {
          schema.at(i).nullable_ = true;
        }
      }
    }
  }
  reader.close();
  input.close();
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

// ---------------------------------------------------------------------------
// Parquet
//
// Everything below reads the format as it is written: the metadata is a thrift
// compact struct at the end of the file, the values of a column live in pages
// that the metadata points at, and both are decoded from their own bytes. No
// part of a file is ever described by guessing at what a writer usually does.
// ---------------------------------------------------------------------------
namespace
{
// The type numbers the thrift compact protocol writes into a field header. They
// belong to that encoding rather than to Parquet, and the whole metadata of a
// Parquet file is written in it.
const int8_t PARQUET_TC_BOOLEAN_TRUE = 1;
const int8_t PARQUET_TC_BOOLEAN_FALSE = 2;
const int8_t PARQUET_TC_BYTE = 3;
const int8_t PARQUET_TC_I16 = 4;
const int8_t PARQUET_TC_I32 = 5;
const int8_t PARQUET_TC_I64 = 6;
const int8_t PARQUET_TC_DOUBLE = 7;
const int8_t PARQUET_TC_BINARY = 8;
const int8_t PARQUET_TC_LIST = 9;
const int8_t PARQUET_TC_SET = 10;
const int8_t PARQUET_TC_MAP = 11;
const int8_t PARQUET_TC_STRUCT = 12;

// How deep a metadata value is allowed to nest. The structures of this format
// nest three levels at most; past this a block is malformed and is refused
// instead of followed further down.
const int64_t PARQUET_MAX_NESTING = 32;

// The first guess at the length of a page header. A header is tens of bytes, so
// doubling from here reaches the real size in a couple of tries and never makes
// a scan read the file twice for one page.
const int64_t PARQUET_HEAD_TRY_LEN = 512;

// The longest block this reader is willing to treat as a page header at all. A
// header is a handful of counts and an encoding, so one that goes past this is
// a file lying about its pages rather than an unusually wordy header.
const int64_t PARQUET_HEAD_MAX_LEN = 64 * 1024;

// A value is refused once it passes this many bytes; it is the same bound the
// record of a row oriented file answers with.
const int64_t PARQUET_MAX_VALUE_LENGTH = 8 * 1024 * 1024;

// A malformed file is reported the way a malformed CSV record is: one 1210
// whose text says what went wrong and, where it is known, at what byte.
int parquet_bad_file(const char *what)
{
  const int ret = OB_INVALID_ARGUMENT;
  char msg[192] = { 0 };
  snprintf(msg, sizeof(msg), "invalid parquet file: %s", what);
  LOG_USER_ERROR(OB_INVALID_ARGUMENT, msg);
  LOG_WARN("invalid parquet file", K(ret), "what", what);
  return ret;
}

int parquet_bad_file_at(const char *what, const int64_t offset)
{
  const int ret = OB_INVALID_ARGUMENT;
  char msg[192] = { 0 };
  snprintf(msg, sizeof(msg), "invalid parquet file: %s at byte %ld", what, offset);
  LOG_USER_ERROR(OB_INVALID_ARGUMENT, msg);
  LOG_WARN("invalid parquet file", K(ret), "what", what, K(offset));
  return ret;
}

// Something the file asks for that this format reader will not invent.
int parquet_unsupported(const char *what)
{
  const int ret = OB_NOT_SUPPORTED;
  LOG_USER_ERROR(OB_NOT_SUPPORTED, what);
  LOG_WARN("unsupported parquet feature", K(ret), "what", what);
  return ret;
}

// The zigzag a compact protocol integer is stored with: the sign is the lowest
// bit, so the magnitude of a negative number is inverted.
int64_t parquet_zigzag(const uint64_t raw)
{
  const uint64_t mask = (0 != (raw & 1)) ? UINT64_MAX : 0;
  return static_cast<int64_t>((raw >> 1) ^ mask);
}

// Little endian integers, assembled byte by byte so the reader does not depend
// on the alignment or the byte order of the machine it runs on.
uint64_t parquet_le_u64(const char *src, const int64_t len)
{
  uint64_t value = 0;
  for (int64_t i = len - 1; i >= 0; --i) {
    value = (value << 8) | static_cast<uint8_t>(src[i]);
  }
  return value;
}

int64_t parquet_le_i64(const char *src, const int64_t len)
{
  const uint64_t raw = parquet_le_u64(src, len);
  int64_t value = 0;
  if (8 == len) {
    value = static_cast<int64_t>(raw);
  } else {
    // flip the top bit and take it back, which sign extends without shifting a
    // value whose width the file states
    const uint64_t sign_bit = 1ULL << (len * 8 - 1);
    value = static_cast<int64_t>((raw ^ sign_bit) - sign_bit);
  }
  return value;
}

double parquet_le_double(const char *src)
{
  const uint64_t raw = parquet_le_u64(src, 8);
  double value = 0;
  MEMCPY(&value, &raw, sizeof(value));
  return value;
}

double parquet_le_float(const char *src)
{
  const uint64_t raw = parquet_le_u64(src, 4);
  float value = 0;
  MEMCPY(&value, &raw, sizeof(value));
  return static_cast<double>(value);
}

// A base 128 varint, which both the thrift compact protocol and the snappy
// block format use for their counts.
int parquet_read_varint(const char *src, const int64_t src_len, int64_t &pos, uint64_t &value)
{
  int ret = OB_SUCCESS;
  uint64_t result = 0;
  int64_t shift = 0;
  value = 0;
  while (OB_SUCC(ret)) {
    if (pos >= src_len) {
      ret = OB_BUF_NOT_ENOUGH;
    } else {
      const uint8_t byte = static_cast<uint8_t>(src[pos]);
      ++pos;
      result |= (static_cast<uint64_t>(byte & 0x7f)) << shift;
      if (0 == (byte & 0x80)) {
        value = result;
        break;
      } else if ((shift += 7) >= 64) {
        ret = OB_INVALID_ARGUMENT;
        LOG_WARN("varint is too long to be a number", K(ret), K(shift), K(pos));
      }
    }
  }
  return ret;
}

// How many bits one level of a page needs. A column that cannot be null has no
// levels at all, which is what a width of zero means here.
int64_t parquet_level_bit_width(const int64_t max_level)
{
  int64_t bits = 0;
  while (max_level >= (1LL << bits)) {
    ++bits;
  }
  return bits;
}

// Hand out len bytes copied from offset bytes back in the block being produced.
// One byte at a time, because a copy is allowed to reach into the bytes the copy
// itself is writing, which is how the format repeats a run.
int parquet_copy_back(common::ObSqlString &out, const int64_t len, const int64_t offset,
                      const int64_t expect_len)
{
  int ret = OB_SUCCESS;
  if (offset <= 0 || offset > out.length() || len <= 0 || out.length() + len > expect_len) {
    ret = parquet_bad_file("copy points outside the bytes already decoded");
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < len; ++i) {
    if (OB_FAIL(out.append(out.ptr() + (out.length() - offset), 1))) {
      LOG_WARN("failed to copy back", K(ret), K(i), K(offset));
    }
  }
  return ret;
}

// The raw snappy block format, which is what the Snappy codec of this file
// format writes: the length of the result as a varint, then a run of literals
// and of copies of bytes the block has already produced. A block that does not
// come out exactly as long as it promised is a broken file, not a hint.
int parquet_snappy_decode(const char *src, const int64_t src_len, const int64_t expect_len,
                          common::ObSqlString &out)
{
  int ret = OB_SUCCESS;
  int64_t pos = 0;
  uint64_t declared = 0;
  out.reset();
  if (src_len < 0 || expect_len < 0) {
    ret = parquet_bad_file("negative page length");
  } else if (OB_FAIL(parquet_read_varint(src, src_len, pos, declared))) {
    ret = (OB_BUF_NOT_ENOUGH == ret) ? parquet_bad_file("truncated compressed block header") : ret;
  } else if (static_cast<int64_t>(declared) != expect_len) {
    ret = parquet_bad_file("compressed block does not promise what the page header states");
  } else if (OB_FAIL(out.reserve(expect_len))) {
    LOG_WARN("failed to reserve uncompressed page", K(ret), K(expect_len));
  } else {
    while (OB_SUCC(ret) && pos < src_len && out.length() < expect_len) {
      const uint8_t tag = static_cast<uint8_t>(src[pos]);
      ++pos;
      switch (tag & 3) {
      case 0: {
        // a literal, whose length is in the tag unless the tag says otherwise
        int64_t len = tag >> 2;
        if (len >= 60) {
          const int64_t len_bytes = len - 59;
          if (pos + len_bytes > src_len) {
            ret = parquet_bad_file_at("literal length runs past the block", pos);
          } else {
            len = static_cast<int64_t>(parquet_le_u64(src + pos, len_bytes)) + 1;
            pos += len_bytes;
          }
        } else {
          ++len;
        }
        if (OB_FAIL(ret)) {
        } else if (len > src_len - pos || out.length() + len > expect_len) {
          ret = parquet_bad_file_at("literal runs past the block", pos);
        } else if (OB_FAIL(out.append(src + pos, len))) {
          LOG_WARN("failed to copy literal", K(ret), K(len));
        } else {
          pos += len;
        }
        break;
      }
      case 1: {
        // copy of 4 to 11 bytes with an eleven bit offset
        uint16_t word = 0;
        if (pos + 2 > src_len) {
          ret = parquet_bad_file_at("copy offset runs past the block", pos);
        } else {
          word = static_cast<uint16_t>(parquet_le_u64(src + pos, 2));
          pos += 2;
        }
        if (OB_FAIL(ret)) {
        } else if (OB_FAIL(parquet_copy_back(out, ((tag >> 2) & 0x07) + 4,
                                             static_cast<int64_t>(word >> 5), expect_len))) {
        }
        break;
      }
      case 2: {
        // copy of up to 64 bytes with a sixteen bit offset
        if (pos + 2 > src_len) {
          ret = parquet_bad_file_at("copy offset runs past the block", pos);
        } else {
          const int64_t offset = static_cast<int64_t>(parquet_le_u64(src + pos, 2));
          pos += 2;
          ret = parquet_copy_back(out, (tag >> 2) + 1, offset, expect_len);
        }
        break;
      }
      default: {
        // copy of up to 64 bytes with a thirty two bit offset
        if (pos + 4 > src_len) {
          ret = parquet_bad_file_at("copy offset runs past the block", pos);
        } else {
          const int64_t offset = static_cast<int64_t>(parquet_le_u64(src + pos, 4));
          pos += 4;
          ret = parquet_copy_back(out, (tag >> 2) + 1, offset, expect_len);
        }
        break;
      }
      }
    }
    if (OB_FAIL(ret)) {
    } else if (out.length() != expect_len || pos != src_len) {
      ret = parquet_bad_file("compressed block does not hold what its header promised");
    }
  }
  return ret;
}

// The run length encoding the format uses for its levels and for a packed
// boolean column. Runs alternate between one value repeated and groups of eight
// values packed into the low bits of each byte, and a run's header says which by
// its lowest bit.
int parquet_hybrid_decode(const char *src, const int64_t src_len, const int64_t bit_width,
                          const int64_t count, common::ObIArray<int64_t> &values,
                          int64_t &consumed)
{
  int ret = OB_SUCCESS;
  int64_t pos = 0;
  int64_t got = 0;
  consumed = 0;
  values.reuse();
  if (count < 0 || bit_width < 0 || bit_width > 32 || src_len < 0) {
    ret = parquet_bad_file("a level block asks for an impossible bit width");
  } else if (0 == bit_width) {
    // nothing is stored: every level of the run is zero, which is the layout of
    // a column that cannot be null
    while (OB_SUCC(ret) && got < count) {
      if (OB_FAIL(values.push_back(0))) {
        LOG_WARN("failed to store level", K(ret), K(got));
      } else {
        ++got;
      }
    }
  } else {
    while (OB_SUCC(ret) && got < count) {
      uint64_t header = 0;
      if (OB_FAIL(parquet_read_varint(src, src_len, pos, header))) {
        ret = (OB_BUF_NOT_ENOUGH == ret)
              ? parquet_bad_file("truncated level block") : ret;
      } else if (0 != (header & 1)) {
        // bit packed run: the header counts groups of eight values
        const int64_t run = static_cast<int64_t>(header >> 1) * 8;
        const int64_t bytes = (run * bit_width + 7) / 8;
        if (run <= 0 || pos + bytes > src_len) {
          ret = parquet_bad_file("bit packed level run runs past its block");
        }
        for (int64_t i = 0; OB_SUCC(ret) && i < run && got < count; ++i) {
          int64_t value = 0;
          int64_t bit = pos * 8 + i * bit_width;
          for (int64_t b = 0; OB_SUCC(ret) && b < bit_width; ++b, ++bit) {
            if (bit / 8 >= src_len) {
              ret = parquet_bad_file("level value runs past its block");
            } else {
              const uint8_t byte = static_cast<uint8_t>(src[bit / 8]);
              value |= (static_cast<int64_t>((byte >> (bit % 8)) & 1)) << b;
            }
          }
          if (OB_FAIL(ret)) {
          } else if (OB_FAIL(values.push_back(value))) {
            LOG_WARN("failed to store level", K(ret), K(i));
          } else {
            ++got;
          }
        }
        if (OB_SUCC(ret)) {
          pos += bytes;
        }
      } else {
        // repeated run: one value, held in as many bytes as the width needs
        const int64_t run = static_cast<int64_t>(header >> 1);
        const int64_t bytes = (bit_width + 7) / 8;
        if (run <= 0 || pos + bytes > src_len) {
          ret = parquet_bad_file("repeated level run runs past its block");
        } else {
          const int64_t value = parquet_le_i64(src + pos, bytes);
          pos += bytes;
          for (int64_t i = 0; OB_SUCC(ret) && i < run && got < count; ++i) {
            if (OB_FAIL(values.push_back(value))) {
              LOG_WARN("failed to store level", K(ret), K(i));
            } else {
              ++got;
            }
          }
        }
      }
    }
  }
  if (OB_SUCC(ret)) {
    consumed = pos;
  }
  return ret;
}

// One element of the schema list of the footer. The list is a depth first
// traversal of a tree flattened into it, so which element is a column and which
// is a group is told by the child count and nothing here needs the tree.
int pq_parse_schema_element(ObThriftCompactReader &reader,
                            ObParquetColumnSchema &column,
                            bool &is_group)
{
  int ret = OB_SUCCESS;
  column.reset();
  is_group = false;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    int32_t value = 0;
    if (1 == field_id) {
      // type: the physical type the values of a column are stored as
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        column.physical_type_ = value;
      }
    } else if (2 == field_id) {
      // type_length
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        column.type_length_ = value;
      }
    } else if (3 == field_id) {
      // repetition_type, which the root of the schema does not carry
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        column.repetition_ = value;
      }
    } else if (4 == field_id) {
      // name
      if (OB_FAIL(reader.read_binary(column.name_))) {
      }
    } else if (5 == field_id) {
      // num_children, whose presence is what makes the element a group
      if (OB_FAIL(reader.read_i32(value))) {
      } else if (value < 0) {
        ret = parquet_bad_file("schema element declares a negative number of children");
      } else {
        column.num_children_ = value;
        is_group = true;
      }
    } else if (6 == field_id) {
      // converted_type: the logical type the writer annotated the element with
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        column.converted_type_ = value;
      }
    } else {
      // scale, precision, field id and the logical type block all land here
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    // the stop byte of the struct
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH == ret) {
    ret = parquet_bad_file("schema element runs past the metadata block");
  } else if (OB_FAIL(ret)) {
    LOG_WARN("failed to read parquet schema element", K(ret), K(field_id), K(type));
  }
  if (OB_SUCC(ret) && !is_group && column.name_.empty()) {
    ret = parquet_bad_file("schema element holds no name");
  }
  return ret;
}

// Where the pages of one column of one row group are, and what is in them.
int pq_parse_column_meta(ObThriftCompactReader &reader, ObParquetChunkLocation &chunk)
{
  int ret = OB_SUCCESS;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  bool has_path = false;
  while (OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    if (2 == field_id) {
      // encodings: which ways of storing levels and values the chunk uses,
      // restated by every page header where it matters
      int8_t elem_type = 0;
      int64_t count = 0;
      if (OB_FAIL(reader.read_list_header(elem_type, count))) {
      }
      for (int64_t i = 0; OB_SUCC(ret) && i < count; ++i) {
        ret = reader.skip(elem_type);
      }
    } else if (3 == field_id) {
      // path_in_schema: the names of the tree the chunk belongs to. A relation
      // built on a flat schema is only ever handed one name, which is the column
      int8_t elem_type = 0;
      int64_t count = 0;
      if (OB_FAIL(reader.read_list_header(elem_type, count))) {
      } else if (PARQUET_TC_BINARY != elem_type) {
        ret = parquet_bad_file("column path is not a list of names");
      } else if (1 != count) {
        ret = parquet_unsupported("parquet column nested inside a group");
      }
      for (int64_t i = 0; OB_SUCC(ret) && i < count; ++i) {
        if (OB_FAIL(reader.read_binary(chunk.path_name_))) {
        } else {
          has_path = true;
        }
      }
    } else if (4 == field_id) {
      // codec
      int32_t value = 0;
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        chunk.codec_ = value;
      }
    } else if (5 == field_id) {
      // num_values
      if (OB_FAIL(reader.read_i64(chunk.num_values_))) {
      }
    } else if (7 == field_id) {
      // total_compressed_size: the bytes of every page the chunk holds, header
      // included, which is the only thing that says where its pages stop
      if (OB_FAIL(reader.read_i64(chunk.total_compressed_size_))) {
      }
    } else if (9 == field_id) {
      // data_page_offset
      if (OB_FAIL(reader.read_i64(chunk.data_page_offset_))) {
      }
    } else if (11 == field_id) {
      // dictionary_page_offset
      if (OB_FAIL(reader.read_i64(chunk.dictionary_page_offset_))) {
      }
    } else {
      // type, the uncompressed size, statistics, the page orders and the bloom filter
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH == ret) {
    ret = parquet_bad_file("column metadata runs past the metadata block");
  } else if (OB_FAIL(ret)) {
    LOG_WARN("failed to read parquet column metadata", K(ret), K(field_id), K(type));
  }
  if (OB_FAIL(ret)) {
  } else if (!has_path) {
    ret = parquet_bad_file("column metadata holds no path");
  } else if (chunk.num_values_ < 0 || chunk.data_page_offset_ < 0) {
    ret = parquet_bad_file("column metadata states a negative count or offset");
  }
  return ret;
}

int pq_parse_column_chunk(ObThriftCompactReader &reader, ObParquetChunkLocation &chunk)
{
  int ret = OB_SUCCESS;
  chunk.reset();
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  bool has_meta = false;
  while (OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    if (1 == field_id) {
      // file_path: a chunk kept in another file is a column this reader cannot
      // open, because a file table names one file at a time
      common::ObString path;
      if (OB_FAIL(reader.read_binary(path))) {
      } else if (!path.empty()) {
        ret = parquet_unsupported("parquet column stored in a separate file");
      }
    } else if (3 == field_id && PARQUET_TC_STRUCT == type) {
      has_meta = true;
      if (OB_FAIL(pq_parse_column_meta(reader, chunk))) {
      }
    } else {
      // file_offset, which the page offsets themselves make redundant, and the
      // index and cryptographic metadata of the chunk
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH == ret) {
    ret = parquet_bad_file("column chunk runs past the metadata block");
  } else if (OB_FAIL(ret)) {
    LOG_WARN("failed to read parquet column chunk", K(ret), K(field_id), K(type));
  }
  if (OB_FAIL(ret)) {
  } else if (!has_meta) {
    ret = parquet_bad_file("column chunk holds no metadata");
  }
  return ret;
}

int pq_parse_row_group(ObThriftCompactReader &reader, ObParquetRowGroup &group)
{
  int ret = OB_SUCCESS;
  group.reset();
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    if (1 == field_id) {
      // columns: one chunk per column of the schema, in the order of the schema
      int8_t elem_type = 0;
      int64_t count = 0;
      if (OB_FAIL(reader.read_list_header(elem_type, count))) {
      } else if (PARQUET_TC_STRUCT != elem_type) {
        ret = parquet_bad_file("row group columns are not a list of chunks");
      }
      for (int64_t i = 0; OB_SUCC(ret) && i < count; ++i) {
        ObParquetChunkLocation chunk;
        chunk.column_index_ = i;
        if (OB_FAIL(pq_parse_column_chunk(reader, chunk))) {
        } else if (OB_FAIL(group.chunks_.push_back(chunk))) {
          LOG_WARN("failed to collect parquet chunk", K(ret), K(i));
        }
      }
    } else if (3 == field_id) {
      // num_rows
      if (OB_FAIL(reader.read_i64(group.num_rows_))) {
      }
    } else {
      // total_byte_size, the sorting columns, the file offset and the ordinal
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH == ret) {
    ret = parquet_bad_file("row group runs past the metadata block");
  } else if (OB_FAIL(ret)) {
    LOG_WARN("failed to read parquet row group", K(ret), K(field_id), K(type));
  }
  if (OB_SUCC(ret) && group.num_rows_ < 0) {
    ret = parquet_bad_file("row group states a negative number of rows");
  }
  return ret;
}

// The metadata block as a whole: the columns, how many rows the file holds and
// where the pages of every row group start.
int pq_parse_file_meta(ObThriftCompactReader &reader, ObParquetFooter &footer)
{
  int ret = OB_SUCCESS;
  footer.reset();
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  bool has_schema = false;
  bool has_rows = false;
  while (OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    if (2 == field_id) {
      has_schema = true;
      // schema: the flattened tree, whose leaves are the columns
      int8_t elem_type = 0;
      int64_t count = 0;
      ObParquetColumnSchema root;
      bool root_is_group = false;
      if (OB_FAIL(reader.read_list_header(elem_type, count))) {
      } else if (PARQUET_TC_STRUCT != elem_type) {
        ret = parquet_bad_file("schema is not a list of elements");
      } else if (count < 1) {
        ret = parquet_bad_file("schema holds no root element");
      } else if (OB_FAIL(pq_parse_schema_element(reader, root, root_is_group))) {
      } else if (!root_is_group) {
        ret = parquet_bad_file("the root of the schema is a column");
      }
      // everything past the root is one of its children: a child of a child
      // would put the values of a column under a tree this relation has no
      // place for
      for (int64_t i = 1; OB_SUCC(ret) && i < count; ++i) {
        ObParquetColumnSchema column;
        bool is_group = false;
        if (i - 1 >= root.num_children_) {
          ret = parquet_unsupported("parquet schema nested deeper than one level");
        } else if (OB_FAIL(pq_parse_schema_element(reader, column, is_group))) {
        } else if (is_group) {
          ret = parquet_unsupported("parquet column nested inside a group");
        } else if (OB_FAIL(footer.columns_.push_back(column))) {
          LOG_WARN("failed to collect parquet column", K(ret), K(i));
        }
      }
      if (OB_SUCC(ret) && root.num_children_ != footer.columns_.count()) {
        ret = parquet_bad_file("schema holds fewer elements than its root declares");
      }
    } else if (3 == field_id) {
      has_rows = true;
      // num_rows
      if (OB_FAIL(reader.read_i64(footer.num_rows_))) {
      }
    } else if (4 == field_id) {
      // row_groups
      int8_t elem_type = 0;
      int64_t count = 0;
      if (OB_FAIL(reader.read_list_header(elem_type, count))) {
      } else if (PARQUET_TC_STRUCT != elem_type) {
        ret = parquet_bad_file("row groups are not a list of groups");
      }
      for (int64_t i = 0; OB_SUCC(ret) && i < count; ++i) {
        ObParquetRowGroup group;
        if (OB_FAIL(pq_parse_row_group(reader, group))) {
        } else if (group.chunks_.count() != footer.columns_.count()) {
          ret = parquet_bad_file("row group does not hold one chunk per column");
        } else if (OB_FAIL(footer.row_groups_.push_back(group))) {
          LOG_WARN("failed to collect parquet row group", K(ret), K(i));
        }
      }
    } else {
      // version, key value metadata, created_by and the column orders
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH == ret) {
    ret = parquet_bad_file("metadata block runs past the end of the file");
  } else if (OB_FAIL(ret)) {
    LOG_WARN("failed to read parquet metadata", K(ret), K(field_id), K(type));
  }
  if (OB_FAIL(ret)) {
  } else if (!has_schema || !has_rows) {
    ret = parquet_bad_file("metadata block holds no schema or no row count");
  } else if (footer.num_rows_ < 0) {
    ret = parquet_bad_file("metadata block states a negative number of rows");
  } else if (footer.columns_.count() > ObFileScanLimits::MAX_COLUMN_COUNT) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("parquet file has too many columns", K(ret), "count",
             footer.columns_.count(), "limit", ObFileScanLimits::MAX_COLUMN_COUNT);
  }
  return ret;
}

// Copy len bytes from offset into out. The window of the handle is refilled as
// it runs out, so a block larger than the window reads the way a small one does
// and a whole file is never held.
int pq_read_range(ObFileInput &input, const int64_t offset, const int64_t len,
                  common::ObSqlString &out)
{
  int ret = OB_SUCCESS;
  out.reset();
  if (offset < 0 || len < 0) {
    ret = parquet_bad_file("negative read range");
  } else if (len > ObFileScanLimits::MAX_PAGE_LENGTH) {
    ret = OB_SIZE_OVERFLOW;
    LOG_WARN("parquet block is too large to read", K(ret), K(len), K(offset),
             "limit", ObFileScanLimits::MAX_PAGE_LENGTH);
  } else if (offset > input.file_size() || len > input.file_size() - offset) {
    ret = parquet_bad_file_at("block lies past the end of the file", offset);
  } else if (OB_FAIL(out.reserve(len))) {
    LOG_WARN("failed to reserve parquet block", K(ret), K(len));
  } else if (OB_FAIL(input.seek(offset))) {
    LOG_WARN("failed to position parquet file", K(ret), K(offset));
  } else {
    int64_t need = len;
    while (OB_SUCC(ret) && need > 0) {
      const common::ObString buffered = input.buffered();
      if (buffered.length() <= 0) {
        if (input.is_eof()) {
          ret = parquet_bad_file_at("file ends before the block it promised",
                                    input.logical_pos());
        } else if (OB_FAIL(input.fill())) {
          if (OB_ITER_END == ret) {
            ret = parquet_bad_file_at("file ends before the block it promised",
                                      input.logical_pos());
          } else {
            LOG_WARN("failed to read parquet block", K(ret));
          }
        }
      } else {
        const int64_t take = (need < buffered.length()) ? need : buffered.length();
        if (OB_FAIL(out.append(buffered.ptr(), take))) {
          LOG_WARN("failed to collect parquet block", K(ret), K(take));
        } else {
          input.consume(take);
          need -= take;
        }
      }
    }
  }
  return ret;
}

// Read and parse the metadata block of an opened file. The names the footer
// hands out point into meta, which the caller therefore has to keep alive.
int pq_load_footer(ObFileInput &input, common::ObSqlString &meta, ObParquetFooter &footer)
{
  int ret = OB_SUCCESS;
  footer.reset();
  const int64_t file_size = input.file_size();
  common::ObSqlString head;
  common::ObSqlString tail;
  if (file_size < 12) {
    ret = parquet_bad_file("file is too short to hold a parquet footer");
  } else if (OB_FAIL(pq_read_range(input, 0, 4, head))) {
    LOG_WARN("failed to read parquet head", K(ret));
  } else if (0 != MEMCMP(head.ptr(), "PAR1", 4)) {
    ret = parquet_bad_file("file does not start with the parquet magic");
  } else if (OB_FAIL(pq_read_range(input, file_size - 8, 8, tail))) {
    LOG_WARN("failed to read parquet tail", K(ret));
  } else if (0 != MEMCMP(tail.ptr() + 4, "PAR1", 4)) {
    ret = parquet_bad_file("file does not end with the parquet magic");
  } else {
    // the four bytes before the closing magic are the length of the block
    const int64_t meta_len = parquet_le_i64(tail.ptr(), 4);
    if (meta_len <= 0) {
      ret = parquet_bad_file("parquet metadata block has no length");
    } else if (meta_len > ObFileScanLimits::MAX_PAGE_LENGTH) {
      ret = OB_SIZE_OVERFLOW;
      LOG_WARN("parquet metadata block is too large", K(ret), K(meta_len));
    } else if (meta_len > file_size - 12) {
      ret = parquet_bad_file("parquet metadata block is longer than the file");
    } else if (OB_FAIL(pq_read_range(input, file_size - 8 - meta_len, meta_len, meta))) {
      LOG_WARN("failed to read parquet metadata block", K(ret), K(meta_len));
    } else {
      ObThriftCompactReader reader;
      reader.init(meta.ptr(), meta.length(), 0);
      if (OB_FAIL(pq_parse_file_meta(reader, footer))) {
      } else if (OB_UNLIKELY(reader.pos() != meta.length())) {
        ret = parquet_bad_file("metadata block holds bytes this reader could not use");
      } else {
        // where the pages of the file end: parsing the block starts by emptying
        // the footer, so the bound has to be stated after it is filled
        footer.data_end_ = file_size - 8 - meta_len;
      }
    }
  }
  return ret;
}

} // end anonymous namespace

int ObFileInput::seek(const int64_t offset)
{
  int ret = OB_SUCCESS;
  if (!is_opened()) {
    ret = OB_NOT_INIT;
    LOG_WARN("file input is not opened", K(ret));
  } else if (offset < 0 || offset > size_) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("offset lies outside the file", K(ret), K(offset), K(size_));
  } else if (static_cast<int64_t>(::lseek(fd_, offset, SEEK_SET)) != offset) {
    ret = OB_IO_ERROR;
    LOG_WARN("failed to position file", K(ret), K(file_path_), K(offset), "errno", errno);
  } else {
    // the window is dropped rather than refilled: what the reader of a columnar
    // file asks for is never the byte the window happens to start at, and a BOM
    // only means something at the head of a file, which this is not
    data_len_ = 0;
    pos_ = 0;
    read_off_ = offset;
    eof_ = (offset >= size_);
    bom_skipped_ = true;
  }
  return ret;
}

int ObThriftCompactReader::read_u8(uint8_t &value)
{
  int ret = OB_SUCCESS;
  if (pos_ >= len_) {
    ret = OB_BUF_NOT_ENOUGH;
  } else {
    value = static_cast<uint8_t>(buf_[pos_]);
    ++pos_;
  }
  return ret;
}

int ObThriftCompactReader::read_varint(uint64_t &value)
{
  int ret = OB_SUCCESS;
  value = 0;
  int64_t shift = 0;
  while (OB_SUCC(ret)) {
    uint8_t byte = 0;
    if (OB_FAIL(read_u8(byte))) {
    } else {
      value |= (static_cast<uint64_t>(byte & 0x7f)) << shift;
      if (0 == (byte & 0x80)) {
        break;
      } else if ((shift += 7) >= 64) {
        ret = OB_INVALID_ARGUMENT;
        LOG_WARN("varint is too long to be a number", K(ret), K(shift), K_(pos));
      }
    }
  }
  return ret;
}

int ObThriftCompactReader::next_field(int64_t &prev_id, int64_t &field_id, int8_t &type)
{
  int ret = OB_SUCCESS;
  uint8_t head = 0;
  if (OB_FAIL(read_u8(head))) {
  } else if (0 == head) {
    // the stop byte, which is how a struct says it is over
    ret = OB_ITER_END;
  } else {
    type = static_cast<int8_t>(head & 0x0f);
    const int64_t delta = (head >> 4) & 0x0f;
    if (delta > 0) {
      field_id = prev_id + delta;
    } else {
      int32_t id = 0;
      if (OB_FAIL(read_i32(id))) {
        LOG_WARN("failed to read field id", K(ret));
      } else {
        field_id = id;
      }
    }
    if (OB_SUCC(ret)) {
      prev_id = field_id;
    }
  }
  return ret;
}

int ObThriftCompactReader::read_i32(int32_t &value)
{
  int ret = OB_SUCCESS;
  int64_t wide = 0;
  value = 0;
  if (OB_FAIL(read_i64(wide))) {
    if (OB_BUF_NOT_ENOUGH != ret) {
      LOG_WARN("failed to read i32", K(ret));
    }
  } else if (wide < INT32_MIN || wide > INT32_MAX) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("i32 field does not fit its width", K(ret), K(wide));
  } else {
    value = static_cast<int32_t>(wide);
  }
  return ret;
}

int ObThriftCompactReader::read_i64(int64_t &value)
{
  int ret = OB_SUCCESS;
  uint64_t raw = 0;
  value = 0;
  if (OB_FAIL(read_varint(raw))) {
    if (OB_BUF_NOT_ENOUGH != ret) {
      LOG_WARN("failed to read i64", K(ret));
    }
  } else {
    value = parquet_zigzag(raw);
  }
  return ret;
}

int ObThriftCompactReader::read_bool(bool &value)
{
  int ret = OB_SUCCESS;
  uint8_t byte = 0;
  value = false;
  if (OB_FAIL(read_u8(byte))) {
  } else if (byte > 1) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("boolean field is not a flag", K(ret), K(byte));
  } else {
    value = (1 == byte);
  }
  return ret;
}

int ObThriftCompactReader::read_double(double &value)
{
  int ret = OB_SUCCESS;
  value = 0;
  if (pos_ + 8 > len_) {
    ret = OB_BUF_NOT_ENOUGH;
  } else {
    value = parquet_le_double(buf_ + pos_);
    pos_ += 8;
  }
  return ret;
}

int ObThriftCompactReader::read_binary(common::ObString &value)
{
  int ret = OB_SUCCESS;
  uint64_t len = 0;
  value.reset();
  if (OB_FAIL(read_varint(len))) {
    if (OB_BUF_NOT_ENOUGH != ret) {
      LOG_WARN("failed to read binary length", K(ret));
    }
  } else if (len > static_cast<uint64_t>(len_ - pos_)) {
    ret = OB_BUF_NOT_ENOUGH;
  } else {
    // the bytes stay where they are: the buffer outlives the reader, so a name
    // read here is as good as one copied
    value.assign_ptr(buf_ + pos_, static_cast<int32_t>(len));
    pos_ += static_cast<int64_t>(len);
  }
  return ret;
}

int ObThriftCompactReader::read_list_header(int8_t &elem_type, int64_t &count)
{
  int ret = OB_SUCCESS;
  uint8_t head = 0;
  elem_type = 0;
  count = 0;
  if (OB_FAIL(read_u8(head))) {
  } else {
    count = head >> 4;
    elem_type = static_cast<int8_t>(head & 0x0f);
    if (15 == count) {
      uint64_t wide = 0;
      if (OB_FAIL(read_varint(wide))) {
        if (OB_BUF_NOT_ENOUGH != ret) {
          LOG_WARN("failed to read list count", K(ret));
        }
      } else {
        count = static_cast<int64_t>(wide);
      }
    }
    // an element takes at least one byte, except a boolean, whose value is the
    // type of the field that holds it; a list longer than the buffer left is
    // therefore a lie about the file
    if (OB_SUCC(ret) && (count < 0
        || (count > len_ - pos_
            && PARQUET_TC_BOOLEAN_TRUE != elem_type
            && PARQUET_TC_BOOLEAN_FALSE != elem_type))) {
      ret = OB_INVALID_ARGUMENT;
      LOG_WARN("list is longer than the metadata block", K(ret), K(count), K_(pos), K_(len));
    }
  }
  return ret;
}

int ObThriftCompactReader::skip(const int8_t type)
{
  return skip_value(type, 0);
}

int ObThriftCompactReader::skip_value(const int8_t type, const int64_t depth)
{
  int ret = OB_SUCCESS;
  if (depth > PARQUET_MAX_NESTING) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("metadata value nests too deep", K(ret), K(depth), K(type));
  } else if (PARQUET_TC_BOOLEAN_TRUE == type || PARQUET_TC_BOOLEAN_FALSE == type) {
    // the value already is the type of the field, so nothing follows it
  } else if (PARQUET_TC_BYTE == type || PARQUET_TC_I16 == type
             || PARQUET_TC_I32 == type || PARQUET_TC_I64 == type) {
    uint64_t raw = 0;
    if (OB_FAIL(read_varint(raw))) {
      if (OB_BUF_NOT_ENOUGH != ret) {
        LOG_WARN("failed to skip integer", K(ret), K(type));
      }
    }
  } else if (PARQUET_TC_DOUBLE == type) {
    if (pos_ + 8 > len_) {
      ret = OB_BUF_NOT_ENOUGH;
    } else {
      pos_ += 8;
    }
  } else if (PARQUET_TC_BINARY == type) {
    uint64_t len = 0;
    if (OB_FAIL(read_varint(len))) {
      if (OB_BUF_NOT_ENOUGH != ret) {
        LOG_WARN("failed to skip binary length", K(ret));
      }
    } else if (len > static_cast<uint64_t>(len_ - pos_)) {
      ret = OB_BUF_NOT_ENOUGH;
    } else {
      pos_ += static_cast<int64_t>(len);
    }
  } else if (PARQUET_TC_LIST == type || PARQUET_TC_SET == type) {
    int8_t elem_type = 0;
    int64_t count = 0;
    if (OB_FAIL(read_list_header(elem_type, count))) {
      if (OB_BUF_NOT_ENOUGH != ret && OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to skip list header", K(ret));
      }
    }
    for (int64_t i = 0; OB_SUCC(ret) && i < count; ++i) {
      if (OB_FAIL(skip_value(elem_type, depth + 1))) {
        if (OB_BUF_NOT_ENOUGH != ret && OB_INVALID_ARGUMENT != ret) {
          LOG_WARN("failed to skip list element", K(ret), K(i));
        }
      }
    }
  } else if (PARQUET_TC_MAP == type) {
    uint64_t size = 0;
    if (OB_FAIL(read_varint(size))) {
      if (OB_BUF_NOT_ENOUGH != ret) {
        LOG_WARN("failed to skip map size", K(ret));
      }
    } else if (size > 0) {
      uint8_t types = 0;
      if (OB_FAIL(read_u8(types))) {
      } else {
        const int8_t key_type = static_cast<int8_t>((types >> 4) & 0x0f);
        const int8_t value_type = static_cast<int8_t>(types & 0x0f);
        for (int64_t i = 0; OB_SUCC(ret) && i < static_cast<int64_t>(size); ++i) {
          if (OB_FAIL(skip_value(key_type, depth + 1))) {
          } else if (OB_FAIL(skip_value(value_type, depth + 1))) {
            if (OB_BUF_NOT_ENOUGH != ret && OB_INVALID_ARGUMENT != ret) {
              LOG_WARN("failed to skip map entry", K(ret), K(i));
            }
          }
        }
      }
    }
  } else if (PARQUET_TC_STRUCT == type) {
    ret = skip_struct(depth + 1);
  } else {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("unknown compact type", K(ret), K(type));
  }
  return ret;
}

int ObThriftCompactReader::skip_struct(const int64_t depth)
{
  int ret = OB_SUCCESS;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(next_field(prev_id, field_id, type))) {
    if (OB_FAIL(skip_value(type, depth))) {
      if (OB_BUF_NOT_ENOUGH != ret && OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to skip field value", K(ret), K(field_id), K(type));
      }
    }
  }
  if (OB_ITER_END == ret) {
    // the stop byte of the struct, which is where a skipped value ends
    ret = OB_SUCCESS;
  } else if (OB_BUF_NOT_ENOUGH != ret && OB_INVALID_ARGUMENT != ret) {
    LOG_WARN("failed to skip struct", K(ret), K(depth));
  }
  return ret;
}

namespace
{

// The file value type one leaf column of a Parquet file is read as. The format
// states the type of every column, so nothing here samples a value to find one;
// equally, a column whose annotation this reader cannot express stops the
// resolve instead of becoming a guess about what the bytes would mean.
int pq_column_value_type(const ObParquetColumnSchema &column, ObFileValueType &type)
{
  int ret = OB_SUCCESS;
  type = FILE_VALUE_VARCHAR;
  if (PARQUET_REP_REPEATED == column.repetition_) {
    ret = parquet_unsupported("parquet column that repeats within a row");
  } else if (PARQUET_TYPE_BOOLEAN == column.physical_type_) {
    if (PARQUET_CONV_NONE == column.converted_type_) {
      type = FILE_VALUE_BOOLEAN;
    } else {
      ret = parquet_unsupported("annotated parquet boolean column");
    }
  } else if (PARQUET_TYPE_INT32 == column.physical_type_) {
    // every integer annotation of a four byte column fits an int64, whether the
    // writer meant it signed or unsigned
    switch (column.converted_type_) {
      case PARQUET_CONV_NONE:
      case PARQUET_CONV_INT_8:
      case PARQUET_CONV_INT_16:
      case PARQUET_CONV_INT_32:
      case PARQUET_CONV_UINT_8:
      case PARQUET_CONV_UINT_16:
      case PARQUET_CONV_UINT_32:
        type = FILE_VALUE_BIGINT;
        break;
      default:
        ret = parquet_unsupported("parquet integer column of an unconvertible logical type");
        break;
    }
  } else if (PARQUET_TYPE_INT64 == column.physical_type_) {
    if (PARQUET_CONV_NONE == column.converted_type_ || PARQUET_CONV_INT_64 == column.converted_type_) {
      type = FILE_VALUE_BIGINT;
    } else {
      // a timestamp, a time, a decimal or a sixty four bit unsigned integer:
      // the number stored is not the value SQL would have to show
      ret = parquet_unsupported("parquet sixty four bit column of an unconvertible logical type");
    }
  } else if (PARQUET_TYPE_FLOAT == column.physical_type_
             || PARQUET_TYPE_DOUBLE == column.physical_type_) {
    if (PARQUET_CONV_NONE == column.converted_type_) {
      type = FILE_VALUE_DOUBLE;
    } else {
      ret = parquet_unsupported("annotated parquet floating point column");
    }
  } else if (PARQUET_TYPE_BYTE_ARRAY == column.physical_type_) {
    switch (column.converted_type_) {
      case PARQUET_CONV_NONE:
      case PARQUET_CONV_UTF8:
      case PARQUET_CONV_JSON:
      case PARQUET_CONV_BSON:
      case PARQUET_CONV_ENUM:
        type = FILE_VALUE_VARCHAR;
        break;
      default:
        ret = parquet_unsupported("parquet byte array column of an unconvertible logical type");
        break;
    }
  } else {
    // INT96 is a timestamp of the oldest layout and a fixed length array holds
    // a decimal or a uuid; neither is a number of the width its bytes state
    ret = parquet_unsupported("parquet column of this physical type");
  }
  return ret;
}

// The bytes of one page as the page header says they decompress. A block that
// does not come out the length promised is a broken file, not a hint.
int pq_decompress(const int64_t codec, const bool is_compressed,
                  const char *src, const int64_t src_len, const int64_t expect_len,
                  common::ObSqlString &out)
{
  int ret = OB_SUCCESS;
  out.reset();
  if (src_len < 0 || expect_len < 0) {
    ret = parquet_bad_file("negative page length");
  } else if (OB_ISNULL(src) && src_len > 0) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("page block has no bytes", K(ret), K(src_len));
  } else if (PARQUET_CODEC_SNAPPY == codec && is_compressed) {
    if (OB_FAIL(parquet_snappy_decode(src, src_len, expect_len, out))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to decompress parquet page", K(ret), K(src_len), K(expect_len));
      }
    }
  } else if (PARQUET_CODEC_UNCOMPRESSED == codec || !is_compressed) {
    if (src_len != expect_len) {
      ret = parquet_bad_file("uncompressed page is not the length its header states");
    } else if (OB_FAIL(out.assign(src, static_cast<int32_t>(expect_len)))) {
      LOG_WARN("failed to copy parquet page", K(ret), K(expect_len));
    }
  } else {
    ret = parquet_unsupported("parquet compression codec");
  }
  return ret;
}

// How many of row_count rows hold a value, which is what the values block of a
// page is measured against: a column that cannot be null has none at all.
int64_t pq_count_present(const common::ObIArray<int64_t> &def_levels,
                         const int64_t max_def_level, const int64_t row_count)
{
  int64_t count = 0;
  if (max_def_level <= 0) {
    count = row_count;
  } else {
    for (int64_t i = 0; i < row_count && i < def_levels.count(); ++i) {
      if (max_def_level == def_levels.at(i)) {
        ++count;
      }
    }
  }
  return count;
}

// DataPageHeader of a version 1 page: the count of rows, the encoding of the
// values and the encoding of each of the two level blocks.
int pq_parse_data_header_v1(ObThriftCompactReader &reader, ObParquetPageHeader &info)
{
  int ret = OB_SUCCESS;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(ret) && OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    int32_t value = 0;
    if (1 == field_id) {
      // num_values, which counts every row of the page, nulls included
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.num_values_ = value;
      }
    } else if (2 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.encoding_ = value;
      }
    } else if (3 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.def_level_encoding_ = value;
      }
    } else if (4 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.rep_level_encoding_ = value;
      }
    } else {
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  }
  return ret;
}

// DictionaryPageHeader: how many values the dictionary holds and how they are
// written. The values themselves are plain, always.
int pq_parse_dictionary_header(ObThriftCompactReader &reader, ObParquetPageHeader &info)
{
  int ret = OB_SUCCESS;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(ret) && OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    int32_t value = 0;
    if (1 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.num_values_ = value;
      }
    } else if (2 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.encoding_ = value;
      }
    } else {
      // is_sorted, which says nothing to a reader that only looks values up
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  }
  return ret;
}

// DataPageHeaderV2: the rows and the values are counted apart, the two level
// blocks are named by length instead of by encoding, and the flag saying the
// values are compressed defaults to true.
int pq_parse_data_header_v2(ObThriftCompactReader &reader, ObParquetPageHeader &info)
{
  int ret = OB_SUCCESS;
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(ret) && OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    int32_t value = 0;
    if (1 == field_id) {
      // num_values, which counts the values stored and not the nulls among the
      // rows the page also states
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.num_values_ = value;
      }
    } else if (2 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.num_nulls_ = value;
      }
    } else if (3 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.num_rows_ = value;
      }
    } else if (4 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.encoding_ = value;
      }
    } else if (5 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.def_level_bytes_ = value;
      }
    } else if (6 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.rep_level_bytes_ = value;
      }
    } else if (7 == field_id) {
      // is_compressed, carried by the type of the field
      info.is_compressed_ = (PARQUET_TC_BOOLEAN_TRUE == type);
    } else {
      // statistics of the page
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    ret = OB_SUCCESS;
  }
  return ret;
}

} // end anonymous namespace

ObParquetScanner::ObParquetScanner()
  : input_(NULL),
    alloc_(NULL),
    columns_(NULL),
    footer_(),
    meta_(),
    states_(),
    row_group_index_(0),
    row_in_group_(0),
    group_rows_(0),
    started_(false)
{
}

ObParquetScanner::~ObParquetScanner()
{
  close();
}

void ObParquetScanner::close()
{
  for (int64_t i = 0; i < states_.count(); ++i) {
    ColumnState *state = states_.at(i);
    if (OB_NOT_NULL(state)) {
      // a page buffer and the cells indexing it allocate for themselves, so they
      // have to be torn down one column at a time rather than with the arena a
      // query resets when it is done
      state->~ColumnState();
      if (OB_NOT_NULL(alloc_)) {
        alloc_->free(state);
      }
    }
  }
  states_.reuse();
  footer_.reset();
  meta_.reset();
  columns_ = NULL;
  input_ = NULL;
  alloc_ = NULL;
  started_ = false;
  row_group_index_ = 0;
  row_in_group_ = 0;
  group_rows_ = 0;
}

int ObParquetScanner::open(ObFileInput &input,
                           const common::ObIArray<ObFileScanColumnDef> &columns)
{
  int ret = OB_SUCCESS;
  close();
  input_ = &input;
  alloc_ = &input.allocator();
  columns_ = &columns;
  if (OB_FAIL(load_footer())) {
    if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
        && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to read parquet metadata", K(ret));
    }
  } else if (columns.count() != footer_.columns_.count()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_USER_ERROR(OB_INVALID_ARGUMENT,
                   "the query does not ask for one column per parquet column");
    LOG_WARN("parquet column count does not match the relation", K(ret),
             "col_cnt", columns.count(), "file_cnt", footer_.columns_.count());
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < columns.count(); ++i) {
    const ObParquetColumnSchema &leaf = footer_.columns_.at(i);
    ObFileValueType value_type = FILE_VALUE_VARCHAR;
    // the name the relation was built with has to be the name of the column it
    // is read from, or a reused plan would hand one column's values to another
    if (!columns.at(i).column_name_.empty()
        && 0 != columns.at(i).column_name_.compare(leaf.name_)) {
      ret = OB_INVALID_ARGUMENT;
      LOG_USER_ERROR(OB_INVALID_ARGUMENT,
                     "parquet column name does not match the relation it was resolved from");
      LOG_WARN("parquet column out of step with the relation", K(ret), K(i),
               "file_name", leaf.name_, "query_name", columns.at(i).column_name_);
    } else if (OB_FAIL(pq_column_value_type(leaf, value_type))) {
      if (OB_NOT_SUPPORTED != ret) {
        LOG_WARN("failed to map parquet column", K(ret), K(i), K(leaf));
      }
    } else {
      void *buf = alloc_->alloc(sizeof(ColumnState));
      if (OB_ISNULL(buf)) {
        ret = OB_ALLOCATE_MEMORY_FAILED;
        LOG_WARN("failed to allocate parquet column state", K(ret), K(i));
      } else {
        ColumnState *state = new (buf) ColumnState();
        state->schema_ = &footer_.columns_.at(i);
        state->max_def_level_ = (PARQUET_REP_OPTIONAL == leaf.repetition_) ? 1 : 0;
        if (OB_FAIL(states_.push_back(state))) {
          LOG_WARN("failed to collect parquet column state", K(ret), K(i));
          state->~ColumnState();
          alloc_->free(state);
        }
      }
    }
  }
  if (OB_SUCC(ret)) {
    started_ = false;
    row_group_index_ = 0;
    row_in_group_ = 0;
    group_rows_ = 0;
  } else {
    close();
  }
  return ret;
}

int ObParquetScanner::rescan()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_) || OB_ISNULL(columns_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("parquet scanner is not opened", K(ret));
  } else if (OB_FAIL(input_->seek_begin())) {
    LOG_WARN("failed to rewind parquet file", K(ret));
  } else {
    // the metadata was read from the end of a file that has not changed, so only
    // the cursors of the columns go back to where their first page is
    for (int64_t i = 0; i < states_.count(); ++i) {
      ColumnState *state = states_.at(i);
      if (OB_NOT_NULL(state)) {
        state->reset_page();
        state->dict_.reuse();
        state->dict_text_.reset();
        state->chunk_ = NULL;
        state->next_page_offset_ = 0;
        state->chunk_end_ = 0;
        state->values_read_ = 0;
        state->rows_read_ = 0;
      }
    }
    started_ = false;
    row_group_index_ = 0;
    row_in_group_ = 0;
    group_rows_ = 0;
  }
  return ret;
}

int ObParquetScanner::read_at(const int64_t offset, const int64_t len, ObSqlString &out)
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("parquet scanner is not opened", K(ret));
  } else if (OB_FAIL(pq_read_range(*input_, offset, len, out))) {
    if (OB_INVALID_ARGUMENT != ret && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to read parquet block", K(ret), K(offset), K(len));
    }
  }
  return ret;
}

int ObParquetScanner::load_footer()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(input_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("parquet scanner is not opened", K(ret));
  } else if (OB_FAIL(pq_load_footer(*input_, meta_, footer_))) {
    if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
        && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to read parquet metadata", K(ret));
    }
  }
  return ret;
}

// Bind the chunks of the current row group to the columns and put every cursor
// back at the first page of its chunk.
int ObParquetScanner::start_row_group()
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(columns_) || OB_ISNULL(alloc_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("parquet scanner is not opened", K(ret));
  } else if (row_group_index_ < 0 || row_group_index_ >= footer_.row_groups_.count()) {
    ret = OB_ITER_END;
  } else {
    const ObParquetRowGroup &group = footer_.row_groups_.at(row_group_index_);
    group_rows_ = group.num_rows_;
    row_in_group_ = 0;
    for (int64_t i = 0; OB_SUCC(ret) && i < states_.count(); ++i) {
      ColumnState *state = states_.at(i);
      if (OB_ISNULL(state) || OB_ISNULL(state->schema_)) {
        ret = OB_ERR_UNEXPECTED;
        LOG_WARN("parquet column has no state", K(ret), K(i));
      } else if (i >= group.chunks_.count() || i >= footer_.columns_.count()) {
        ret = OB_ERR_UNEXPECTED;
        LOG_WARN("parquet row group holds no chunk for a column", K(ret), K(i));
      } else {
        const ObParquetChunkLocation &chunk = group.chunks_.at(i);
        const ObParquetColumnSchema &leaf = footer_.columns_.at(i);
        // a row group whose chunks are listed in another order than the schema
        // would give one column the pages of another, which is a wrong result
        // rather than an error, so the name each chunk carries decides
        if (0 != chunk.path_name_.compare(leaf.name_)) {
          ret = parquet_bad_file("the chunks of a row group are not in the order of the schema");
        } else {
          state->chunk_ = &group.chunks_.at(i);
          state->reset_page();
          state->dict_.reuse();
          state->dict_text_.reset();
          state->values_read_ = 0;
          state->rows_read_ = 0;
          state->next_page_offset_ = (state->chunk_->dictionary_page_offset_ >= 0
                                      ? state->chunk_->dictionary_page_offset_
                                      : state->chunk_->data_page_offset_);
          // the size the footer states for the chunk is what ends its pages: a
          // writer may leave anything at all between the last page and the
          // metadata, and the end of the data is no bound a page can be checked
          // against without mistaking that for one more page
          state->chunk_end_ = (state->chunk_->total_compressed_size_ > 0
                               && state->next_page_offset_
                                  <= footer_.data_end_ - state->chunk_->total_compressed_size_
                               ? state->next_page_offset_ + state->chunk_->total_compressed_size_
                               : footer_.data_end_);
          if (state->next_page_offset_ < 0 || state->next_page_offset_ > footer_.data_end_) {
            ret = parquet_bad_file_at("column chunk points outside the data of the file",
                                      state->next_page_offset_);
          }
        }
      }
    }
  }
  return ret;
}

// The rows of a file leave in the order its row groups are listed, and one row
// is laid out by the columns of the relation, projected or not.
int ObParquetScanner::next_row(common::ObIArray<common::ObString> &row)
{
  int ret = OB_SUCCESS;
  row.reuse();
  if (OB_ISNULL(input_) || OB_ISNULL(columns_) || OB_ISNULL(alloc_)) {
    ret = OB_NOT_INIT;
    LOG_WARN("parquet scanner is not opened", K(ret));
  } else {
    bool got = false;
    while (OB_SUCC(ret) && !got) {
      if (!started_) {
        if (row_group_index_ >= footer_.row_groups_.count()) {
          ret = OB_ITER_END;
        } else if (OB_FAIL(start_row_group())) {
          if (OB_ITER_END != ret && OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret) {
            LOG_WARN("failed to start parquet row group", K(ret), K_(row_group_index));
          }
        } else {
          started_ = true;
        }
      } else if (row_in_group_ >= group_rows_) {
        // the group is drained; the next pass of this loop opens the one after
        started_ = false;
        ++row_group_index_;
      } else {
        for (int64_t i = 0; OB_SUCC(ret) && i < states_.count(); ++i) {
          ColumnState &state = *states_.at(i);
          common::ObString value;
          if (!columns_->at(i).projected_) {
            // nothing reads this column, so the pages of the file that hold it
            // are never opened; the value handed back is a null no caller looks at
          } else if (OB_FAIL(ensure_page(state, row_in_group_))) {
            if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
                && OB_SIZE_OVERFLOW != ret) {
              LOG_WARN("failed to read parquet page", K(ret), K(i), K_(row_in_group));
            }
          } else {
            const int64_t slot = row_in_group_ - state.page_first_row_;
            if (slot < 0 || slot >= state.cells_.count()) {
              ret = OB_ERR_UNEXPECTED;
              LOG_WARN("parquet page does not hold the row asked for", K(ret), K(i),
                       K(slot), "cell_cnt", state.cells_.count(),
                       "page_first_row", state.page_first_row_,
                       "page_rows", state.page_row_count_);
            } else {
              const ObParquetCell &cell = state.cells_.at(slot);
              if (!cell.is_null_) {
                if (cell.off_ < 0 || cell.len_ < 0
                    || cell.off_ + cell.len_ > state.text_.length()) {
                  ret = OB_ERR_UNEXPECTED;
                  LOG_WARN("parquet cell points outside its page buffer", K(ret), K(i), K(cell));
                } else {
                  // a value of no bytes is still a value: only a cell marked null
                  // leaves as one, and an empty buffer has no pointer to point at
                  value.assign_ptr((0 == cell.len_) ? "" : state.text_.ptr() + cell.off_,
                                   static_cast<int32_t>(cell.len_));
                }
              }
            }
          }
          if (OB_FAIL(ret)) {
          } else if (OB_FAIL(row.push_back(value))) {
            LOG_WARN("failed to hand out parquet value", K(ret), K(i));
          }
        }
        if (OB_SUCC(ret)) {
          ++row_in_group_;
          got = true;
        }
      }
    }
  }
  return ret;
}

// Decode pages of one column until the row of the row group asked for has a
// cell. The row group says how many rows there are and the chunk says how many
// bytes of pages it has, so a column stops at whichever of the two runs out.
int ObParquetScanner::ensure_page(ColumnState &state, const int64_t row)
{
  int ret = OB_SUCCESS;
  while (OB_SUCC(ret)
         && (state.page_row_count_ <= 0
             || row < state.page_first_row_
             || row >= state.page_first_row_ + state.page_row_count_)) {
    if (state.rows_read_ >= group_rows_ || state.next_page_offset_ >= state.chunk_end_) {
      ret = OB_ITER_END;
    } else if (OB_FAIL(load_page(state))) {
      if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
          && OB_SIZE_OVERFLOW != ret && OB_ITER_END != ret) {
        LOG_WARN("failed to decode parquet page", K(ret), K(row),
                 "rows_read", state.rows_read_, "offset", state.next_page_offset_);
      }
    }
  }
  if (OB_ITER_END == ret) {
    ret = parquet_bad_file("parquet column chunk holds fewer rows than its row group states");
  }
  return ret;
}

// Read and decode the page the cursor of one column is on. A dictionary page
// holds values but no rows, so reading one leaves the row count of the column
// where it was and the pass goes on to the page behind it.
int ObParquetScanner::load_page(ColumnState &state)
{
  int ret = OB_SUCCESS;
  if (OB_ISNULL(state.chunk_) || OB_ISNULL(state.schema_)) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("parquet column is not bound to a chunk", K(ret));
  } else {
    bool done = false;
    while (OB_SUCC(ret) && !done) {
      const int64_t offset = state.next_page_offset_;
      ObParquetPageHeader info;
      ObSqlString body;
      if (OB_FAIL(read_page(offset, info, body))) {
        if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
            && OB_SIZE_OVERFLOW != ret) {
          LOG_WARN("failed to read parquet page", K(ret), K(offset));
        }
      } else if (info.header_length_ + info.compressed_size_ > state.chunk_end_ - offset) {
        // the footer counted the pages of this chunk, so a page the count does
        // not cover is not one more page of it but the bytes of something else
        ret = parquet_bad_file("parquet page runs past the chunk that holds it");
      } else if (PARQUET_PAGE_DICTIONARY == info.page_type_) {
        if (OB_FAIL(decode_dictionary(state, info, body.ptr(), body.length()))) {
          if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
              && OB_SIZE_OVERFLOW != ret) {
            LOG_WARN("failed to decode parquet dictionary page", K(ret), K(offset));
          }
        } else {
          state.next_page_offset_ = offset + info.header_length_ + info.compressed_size_;
        }
      } else if (PARQUET_PAGE_DATA == info.page_type_
                 || PARQUET_PAGE_DATA_V2 == info.page_type_) {
        if (OB_FAIL(decode_values(state, info, body.ptr(), body.length()))) {
          if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
              && OB_SIZE_OVERFLOW != ret) {
            LOG_WARN("failed to decode parquet data page", K(ret), K(offset));
          }
        } else {
          state.next_page_offset_ = offset + info.header_length_ + info.compressed_size_;
          done = true;
        }
      } else {
        ret = parquet_unsupported("parquet page of this type");
      }
    }
  }
  return ret;
}

// One page header and the body it describes. A header is not prefixed by its
// own length, so the bytes around it are read tentatively and the read grows
// once more when the parse runs off the end of them.
int ObParquetScanner::read_page(const int64_t offset, ObParquetPageHeader &info,
                                ObSqlString &body)
{
  int ret = OB_SUCCESS;
  ObSqlString head;
  const int64_t remaining = footer_.data_end_ - offset;
  int64_t try_len = PARQUET_HEAD_TRY_LEN;
  bool parsed = false;
  info.reset();
  body.reset();
  if (offset < 0 || offset >= footer_.data_end_) {
    ret = parquet_bad_file_at("page lies outside the data of the file", offset);
  }
  while (OB_SUCC(ret) && !parsed) {
    const int64_t want = (try_len < remaining) ? try_len : remaining;
    if (OB_FAIL(read_at(offset, want, head))) {
      if (OB_INVALID_ARGUMENT != ret && OB_SIZE_OVERFLOW != ret) {
        LOG_WARN("failed to read parquet page header", K(ret), K(offset), K(want));
      }
    } else {
      const int tmp_ret = parse_page_header(head.ptr(), head.length(), info);
      if (OB_SUCCESS == tmp_ret) {
        parsed = true;
      } else if (OB_BUF_NOT_ENOUGH == tmp_ret) {
        if (want >= remaining || want >= PARQUET_HEAD_MAX_LEN) {
          ret = parquet_bad_file("parquet page header runs past the data of the file");
        } else {
          try_len = (2 * want < PARQUET_HEAD_MAX_LEN) ? 2 * want : PARQUET_HEAD_MAX_LEN;
        }
      } else {
        ret = tmp_ret;
      }
    }
  }
  if (OB_FAIL(ret)) {
  } else if (info.header_length_ <= 0 || info.header_length_ > head.length()) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("parquet page header length is not the bytes it took", K(ret), K(info));
  } else if (info.compressed_size_ > remaining - info.header_length_) {
    ret = parquet_bad_file("parquet page body runs past the data of the file");
  } else if (OB_FAIL(read_at(offset + info.header_length_, info.compressed_size_, body))) {
    if (OB_INVALID_ARGUMENT != ret && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to read parquet page body", K(ret), K(info));
    }
  }
  return ret;
}

// The thrift compact struct in front of one page. OB_BUF_NOT_ENOUGH is left to
// mean what it says: the header may be longer than the buffer tried for it, so
// the caller reads further and parses again.
int ObParquetScanner::parse_page_header(const char *buf, const int64_t buf_len,
                                        ObParquetPageHeader &info)
{
  int ret = OB_SUCCESS;
  info.reset();
  ObThriftCompactReader reader;
  reader.init(buf, buf_len, 0);
  int64_t prev_id = 0;
  int64_t field_id = 0;
  int8_t type = 0;
  while (OB_SUCC(ret) && OB_SUCC(reader.next_field(prev_id, field_id, type))) {
    int32_t value = 0;
    if (1 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.page_type_ = value;
      }
    } else if (2 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.uncompressed_size_ = value;
      }
    } else if (3 == field_id) {
      if (OB_FAIL(reader.read_i32(value))) {
      } else {
        info.compressed_size_ = value;
      }
    } else if (5 == field_id && PARQUET_TC_STRUCT == type) {
      ret = pq_parse_data_header_v1(reader, info);
    } else if (7 == field_id && PARQUET_TC_STRUCT == type) {
      ret = pq_parse_dictionary_header(reader, info);
    } else if (8 == field_id && PARQUET_TC_STRUCT == type) {
      ret = pq_parse_data_header_v2(reader, info);
    } else {
      // the checksum, the column index offsets and whatever a newer library
      // writes where this one has no field
      ret = reader.skip(type);
    }
  }
  if (OB_ITER_END == ret) {
    info.header_length_ = reader.pos();
    ret = OB_SUCCESS;
    if (info.compressed_size_ < 0 || info.uncompressed_size_ < 0) {
      ret = parquet_bad_file("parquet page header states a negative size");
    } else if (info.compressed_size_ > ObFileScanLimits::MAX_PAGE_LENGTH
               || info.uncompressed_size_ > ObFileScanLimits::MAX_PAGE_LENGTH) {
      ret = OB_SIZE_OVERFLOW;
      LOG_WARN("parquet page is too large to read", K(ret), K(info),
               "limit", ObFileScanLimits::MAX_PAGE_LENGTH);
    }
  } else if (OB_BUF_NOT_ENOUGH != ret) {
    if (OB_INVALID_ARGUMENT == ret) {
      ret = parquet_bad_file("parquet page header is malformed");
    } else {
      LOG_WARN("failed to read parquet page header", K(ret), K(field_id), K(type));
    }
  }
  return ret;
}

int ObParquetScanner::decode_levels(const char *src, const int64_t src_len,
                                    const int64_t bit_width, const int64_t count,
                                    common::ObIArray<int64_t> &levels,
                                    int64_t &consumed)
{
  int ret = OB_SUCCESS;
  if (OB_FAIL(parquet_hybrid_decode(src, src_len, bit_width, count, levels, consumed))) {
    if (OB_INVALID_ARGUMENT != ret) {
      LOG_WARN("failed to decode parquet levels", K(ret), K(bit_width), K(count), K(src_len));
    }
  } else if (count != levels.count()) {
    ret = parquet_bad_file("parquet level block holds fewer levels than the page counts");
  }
  return ret;
}

// The dictionary of one column chunk: a plain list of values, held in a buffer
// of its own because the pages that index it live beside it, not inside it.
int ObParquetScanner::decode_dictionary(ColumnState &state, const ObParquetPageHeader &info,
                                        const char *body, const int64_t body_len)
{
  int ret = OB_SUCCESS;
  ObSqlString plain;
  ObFileValueType value_type = FILE_VALUE_VARCHAR;
  state.dict_.reuse();
  state.dict_text_.reset();
  if (OB_ISNULL(state.chunk_) || OB_ISNULL(state.schema_)) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("parquet column is not bound to a chunk", K(ret));
  } else if (PARQUET_ENC_PLAIN != info.encoding_) {
    ret = parquet_unsupported("parquet dictionary page that is not plain encoded");
  } else if (info.num_values_ < 0) {
    ret = parquet_bad_file("parquet dictionary page states a negative count");
  } else if (OB_FAIL(pq_column_value_type(*state.schema_, value_type))) {
  } else if (OB_FAIL(pq_decompress(state.chunk_->codec_, true, body, body_len,
                                   info.uncompressed_size_, plain))) {
    if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to decompress parquet dictionary", K(ret), K(info));
    }
  } else {
    int64_t pos = 0;
    for (int64_t i = 0; OB_SUCC(ret) && i < info.num_values_; ++i) {
      ObParquetCell cell;
      if (OB_FAIL(read_value(*state.schema_, state.dict_text_, plain.ptr(),
                             plain.length(), pos, cell))) {
        if (OB_INVALID_ARGUMENT != ret) {
          LOG_WARN("failed to read parquet dictionary value", K(ret), K(i), K(pos));
        }
      } else if (OB_FAIL(state.dict_.push_back(cell))) {
        LOG_WARN("failed to collect parquet dictionary value", K(ret), K(i));
      }
    }
  }
  return ret;
}

// The rows of one data page: the levels first, because they decide which rows
// hold a value at all, then the values the two page versions lay out apart.
int ObParquetScanner::decode_values(ColumnState &state, const ObParquetPageHeader &info,
                                    const char *body, const int64_t body_len)
{
  int ret = OB_SUCCESS;
  const bool is_v2 = (PARQUET_PAGE_DATA_V2 == info.page_type_);
  ObSqlString plain;
  common::ObSEArray<int64_t, 64> def_levels;
  const char *values = NULL;
  int64_t values_len = 0;
  int64_t row_count = 0;
  const int64_t max_def = state.max_def_level_;
  const int64_t page_first = state.rows_read_;
  state.reset_page();
  state.page_first_row_ = page_first;
  if (OB_ISNULL(state.chunk_) || OB_ISNULL(state.schema_)) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("parquet column is not bound to a chunk", K(ret));
  } else if (info.num_values_ < 0) {
    ret = parquet_bad_file("parquet data page states a negative count");
  } else if (is_v2) {
    // a version 2 page keeps its levels in front of the values, uncompressed,
    // and states how long each of the two blocks is; a flat schema has none
    if (0 != info.rep_level_bytes_) {
      ret = parquet_unsupported("parquet data page with repetition levels");
    } else if (info.def_level_bytes_ > body_len) {
      ret = parquet_bad_file("parquet page levels run past its body");
    } else if (info.num_rows_ < 0 || info.num_nulls_ < 0
               || info.num_rows_ != info.num_values_ + info.num_nulls_) {
      ret = parquet_bad_file("parquet data page counts its rows and its values apart");
    } else {
      row_count = info.num_rows_;
      int64_t consumed = 0;
      if (0 == max_def && 0 != info.def_level_bytes_) {
        ret = parquet_bad_file("parquet page holds levels for a column that cannot be null");
      } else if (max_def > 0
                 && OB_FAIL(decode_levels(body, info.def_level_bytes_,
                                          parquet_level_bit_width(max_def), row_count,
                                          def_levels, consumed))) {
      } else if (max_def > 0 && consumed != info.def_level_bytes_) {
        ret = parquet_bad_file("parquet page levels do not fill the bytes its header states");
      }
      if (OB_FAIL(ret)) {
      } else {
        const int64_t values_at = info.def_level_bytes_;
        const int64_t expect_len = info.uncompressed_size_ - values_at;
        if (expect_len < 0) {
          ret = parquet_bad_file("parquet page is smaller uncompressed than its levels alone");
        } else if (OB_FAIL(pq_decompress(state.chunk_->codec_, info.is_compressed_,
                                         body + values_at, body_len - values_at,
                                         expect_len, plain))) {
          if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
              && OB_SIZE_OVERFLOW != ret) {
            LOG_WARN("failed to decompress parquet values", K(ret), K(info));
          }
        } else {
          values = plain.ptr();
          values_len = plain.length();
        }
      }
    }
  } else {
    // a version 1 page holds both level blocks inside the compressed body, each
    // one prefixed by the bit width its levels were packed with. The width is
    // taken from the page rather than computed from the schema, which is what
    // the layout says a reader should do.
    if (OB_FAIL(pq_decompress(state.chunk_->codec_, true, body, body_len,
                              info.uncompressed_size_, plain))) {
      if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret && OB_SIZE_OVERFLOW != ret) {
        LOG_WARN("failed to decompress parquet page", K(ret), K(info));
      }
    } else {
      row_count = info.num_values_;
      int64_t pos = 0;
      int64_t consumed = 0;
      int64_t width = 0;
      // the repetition levels of a flat schema are all zero, which is a block of
      // nothing behind a byte saying so
      if (pos + 1 > plain.length()) {
        ret = parquet_bad_file("parquet data page holds no repetition level block");
      } else {
        width = static_cast<uint8_t>(plain.ptr()[pos]);
        ++pos;
        if (0 != width) {
          ret = parquet_unsupported("parquet data page with repetition levels");
        }
      }
      if (OB_FAIL(ret)) {
      } else if (pos + 1 > plain.length()) {
        ret = parquet_bad_file("parquet data page holds no definition level block");
      } else {
        width = static_cast<uint8_t>(plain.ptr()[pos]);
        ++pos;
        if (width > 0 && 0 == max_def) {
          ret = parquet_bad_file("parquet page holds levels for a column that cannot be null");
        } else if (width > 0
                   && OB_FAIL(decode_levels(plain.ptr() + pos, plain.length() - pos, width,
                                            row_count, def_levels, consumed))) {
        } else if (width > 0) {
          pos += consumed;
        } else if (max_def > 0) {
          ret = parquet_bad_file("parquet levels of a nullable column are packed in no bits");
        }
      }
      if (OB_SUCC(ret)) {
        values = plain.ptr() + pos;
        values_len = plain.length() - pos;
      }
    }
  }
  if (OB_FAIL(ret)) {
  } else if (row_count <= 0) {
    ret = parquet_bad_file("parquet data page holds no row");
  } else if (PARQUET_ENC_PLAIN == info.encoding_) {
    if (OB_FAIL(format_plain(*state.schema_, state.text_, state.cells_, values, values_len,
                             def_levels, max_def, row_count))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to read parquet values", K(ret), K(info), K(row_count));
      }
    }
  } else if (PARQUET_ENC_RLE_DICTIONARY == info.encoding_) {
    if (state.dict_.count() <= 0) {
      ret = parquet_bad_file("parquet index page read before the dictionary it indexes");
    } else if (OB_FAIL(format_dictionary(state, values, values_len, def_levels,
                                         max_def, row_count))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to read parquet indexes", K(ret), K(info), K(row_count));
      }
    }
  } else {
    // the legacy dictionary encoding puts the levels inside the block of
    // indexes, and the delta and byte stream splittings each need a decoder of
    // their own; none of them is guessed at
    ret = parquet_unsupported("parquet data page encoding");
  }
  if (OB_SUCC(ret)) {
    state.page_first_row_ = page_first;
    state.page_row_count_ = row_count;
    state.rows_read_ += row_count;
    state.values_read_ += pq_count_present(def_levels, max_def, row_count);
  }
  return ret;
}

// Cells for every row of one plain encoded page, in the order of the rows. The
// text of a value goes into the buffer of the column and the cell keeps where
// in it the value landed, so handing a row out copies nothing.
int ObParquetScanner::format_plain(const ObParquetColumnSchema &schema, ObSqlString &text,
                                   common::ObIArray<ObParquetCell> &cells,
                                   const char *values, const int64_t values_len,
                                   const common::ObIArray<int64_t> &def_levels,
                                   const int64_t max_def_level, const int64_t row_count)
{
  int ret = OB_SUCCESS;
  int64_t pos = 0;
  for (int64_t r = 0; OB_SUCC(ret) && r < row_count; ++r) {
    ObParquetCell cell;
    const bool present = (max_def_level <= 0)
                         || (r < def_levels.count() && max_def_level == def_levels.at(r));
    if (!present) {
      cell.is_null_ = true;
    } else if (OB_FAIL(read_value(schema, text, values, values_len, pos, cell))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to read parquet value", K(ret), K(r), K(pos), K(schema));
      }
    }
    if (OB_FAIL(ret)) {
    } else if (OB_FAIL(cells.push_back(cell))) {
      LOG_WARN("failed to collect parquet cell", K(ret), K(r));
    }
  }
  return ret;
}

// Cells for every row of a page whose values the dictionary page already
// turned into text: one index per value, packed the way the levels are.
int ObParquetScanner::format_dictionary(ColumnState &state,
                                        const char *index_bytes, const int64_t index_len,
                                        const common::ObIArray<int64_t> &def_levels,
                                        const int64_t max_def_level, const int64_t row_count)
{
  int ret = OB_SUCCESS;
  common::ObSEArray<int64_t, 64> indexes;
  int64_t consumed = 0;
  const int64_t value_count = pq_count_present(def_levels, max_def_level, row_count);
  if (index_len < 1) {
    ret = parquet_bad_file("parquet index page holds no block of indexes");
  } else {
    const int64_t width = static_cast<uint8_t>(index_bytes[0]);
    if (OB_FAIL(decode_levels(index_bytes + 1, index_len - 1, width, value_count,
                              indexes, consumed))) {
      if (OB_INVALID_ARGUMENT != ret) {
        LOG_WARN("failed to decode parquet indexes", K(ret), K(width), K(value_count));
      }
    } else {
      int64_t slot = 0;
      for (int64_t r = 0; OB_SUCC(ret) && r < row_count; ++r) {
        ObParquetCell cell;
        const bool present = (max_def_level <= 0)
                             || (r < def_levels.count() && max_def_level == def_levels.at(r));
        if (!present) {
          cell.is_null_ = true;
        } else if (slot >= indexes.count()) {
          ret = parquet_bad_file("parquet index block holds fewer indexes than values");
        } else {
          const int64_t dict_slot = indexes.at(slot);
          ++slot;
          if (dict_slot < 0 || dict_slot >= state.dict_.count()) {
            ret = parquet_bad_file("parquet dictionary index names no value in the dictionary");
          } else {
            const ObParquetCell &entry = state.dict_.at(dict_slot);
            cell.off_ = state.text_.length();
            cell.len_ = entry.len_;
            if (entry.off_ < 0 || entry.len_ < 0
                || entry.off_ + entry.len_ > state.dict_text_.length()) {
              ret = OB_ERR_UNEXPECTED;
              LOG_WARN("parquet dictionary value points outside its buffer", K(ret),
                       K(dict_slot), K(entry));
            } else if (entry.len_ > 0
                       && OB_FAIL(state.text_.append(state.dict_text_.ptr() + entry.off_,
                                                     entry.len_))) {
              LOG_WARN("failed to copy parquet dictionary value", K(ret), K(dict_slot));
            }
          }
        }
        if (OB_FAIL(ret)) {
        } else if (OB_FAIL(state.cells_.push_back(cell))) {
          LOG_WARN("failed to collect parquet cell", K(ret), K(r));
        }
      }
    }
  }
  return ret;
}

// One value of the physical type the footer gave the column, written as the
// text the parser of its inferred type accepts. The position moves by the bytes
// the value took, except for a boolean, of which eight share one byte.
int ObParquetScanner::read_value(const ObParquetColumnSchema &schema, ObSqlString &text,
                                 const char *src, const int64_t src_len, int64_t &pos,
                                 ObParquetCell &cell)
{
  int ret = OB_SUCCESS;
  cell.reset();
  if (OB_ISNULL(src) && src_len > 0) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("parquet value block has no bytes", K(ret), K(src_len));
  } else if (PARQUET_TYPE_BOOLEAN == schema.physical_type_) {
    // bits are numbered from the low end of each byte, which is the order the
    // format packs them in
    const int64_t byte = pos / 8;
    const int64_t bit = pos % 8;
    if (byte < 0 || byte >= src_len) {
      ret = parquet_bad_file("parquet boolean value runs past its page");
    } else {
      const uint8_t packed = static_cast<uint8_t>(src[byte]);
      ++pos;
      ret = append_bool(text, 0 != ((packed >> bit) & 1), cell);
    }
  } else if (PARQUET_TYPE_INT32 == schema.physical_type_
             || PARQUET_TYPE_FLOAT == schema.physical_type_) {
    if (pos + 4 > src_len) {
      ret = parquet_bad_file("parquet four byte value runs past its page");
    } else if (PARQUET_TYPE_FLOAT == schema.physical_type_) {
      ret = append_double(text, parquet_le_float(src + pos), cell);
      pos += 4;
    } else {
      const bool is_unsigned = (PARQUET_CONV_UINT_8 == schema.converted_type_
                                 || PARQUET_CONV_UINT_16 == schema.converted_type_
                                 || PARQUET_CONV_UINT_32 == schema.converted_type_);
      const int64_t value = is_unsigned ? static_cast<int64_t>(parquet_le_u64(src + pos, 4))
                                        : parquet_le_i64(src + pos, 4);
      ret = append_number(text, value, cell);
      pos += 4;
    }
  } else if (PARQUET_TYPE_INT64 == schema.physical_type_
             || PARQUET_TYPE_DOUBLE == schema.physical_type_) {
    if (pos + 8 > src_len) {
      ret = parquet_bad_file("parquet eight byte value runs past its page");
    } else if (PARQUET_TYPE_DOUBLE == schema.physical_type_) {
      ret = append_double(text, parquet_le_double(src + pos), cell);
      pos += 8;
    } else {
      ret = append_number(text, parquet_le_i64(src + pos, 8), cell);
      pos += 8;
    }
  } else if (PARQUET_TYPE_BYTE_ARRAY == schema.physical_type_) {
    if (pos + 4 > src_len) {
      ret = parquet_bad_file("parquet value length runs past its page");
    } else {
      const int64_t len = static_cast<int64_t>(parquet_le_u64(src + pos, 4));
      pos += 4;
      if (len < 0 || len > PARQUET_MAX_VALUE_LENGTH) {
        ret = parquet_bad_file("parquet string value is longer than any record may hold");
      } else if (len > src_len - pos) {
        ret = parquet_bad_file("parquet string value runs past its page");
      } else {
        ret = append_text(text, src + pos, len, cell);
        pos += len;
      }
    }
  } else {
    ret = parquet_bad_file("parquet column has a physical type this reader was not built for");
  }
  return ret;
}

int ObParquetScanner::append_number(ObSqlString &text, const int64_t value,
                                    ObParquetCell &cell)
{
  int ret = OB_SUCCESS;
  cell.off_ = text.length();
  if (OB_FAIL(text.append_fmt("%ld", value))) {
    LOG_WARN("failed to write parquet integer", K(ret), K(value));
  } else {
    cell.len_ = text.length() - cell.off_;
  }
  return ret;
}

int ObParquetScanner::append_double(ObSqlString &text, const double value,
                                    ObParquetCell &cell)
{
  int ret = OB_SUCCESS;
  cell.off_ = text.length();
  // fifteen significant digits round-trip a double the way its writer meant it,
  // and 1.5 does not come out as 1.5000000000000002
  if (OB_FAIL(text.append_fmt("%.15g", value))) {
    LOG_WARN("failed to write parquet float", K(ret), K(value));
  } else {
    cell.len_ = text.length() - cell.off_;
  }
  return ret;
}

int ObParquetScanner::append_bool(ObSqlString &text, const bool value, ObParquetCell &cell)
{
  int ret = OB_SUCCESS;
  cell.off_ = text.length();
  if (OB_FAIL(text.append(value ? "true" : "false", value ? 4 : 5))) {
    LOG_WARN("failed to write parquet boolean", K(ret), K(value));
  } else {
    cell.len_ = text.length() - cell.off_;
  }
  return ret;
}

int ObParquetScanner::append_text(ObSqlString &text, const char *value, const int64_t len,
                                  ObParquetCell &cell)
{
  int ret = OB_SUCCESS;
  cell.off_ = text.length();
  if (len > 0 && OB_FAIL(text.append(value, len))) {
    LOG_WARN("failed to write parquet string", K(ret), K(len));
  } else {
    cell.len_ = text.length() - cell.off_;
  }
  return ret;
}

// The schema a Parquet file declares for itself, read from the footer alone:
// nothing of the file's rows is looked at, because the file states the type of
// every column it holds.
int ObFileScanUtils::read_parquet_schema(common::ObIAllocator &alloc,
                                         const common::ObString &real_path,
                                         common::ObIArray<common::ObString> &names,
                                         common::ObIArray<ObFileColumnSchema> &schema)
{
  int ret = OB_SUCCESS;
  ObFileInput input;
  ObSqlString meta;
  ObParquetFooter footer;
  names.reuse();
  schema.reuse();
  if (real_path.empty()) {
    ret = OB_INVALID_ARGUMENT;
    LOG_WARN("invalid resolved path", K(ret), K(real_path));
  } else if (OB_FAIL(input.open(alloc, real_path))) {
    LOG_WARN("failed to open file for parquet schema", K(ret), K(real_path));
  } else if (OB_FAIL(pq_load_footer(input, meta, footer))) {
    if (OB_INVALID_ARGUMENT != ret && OB_NOT_SUPPORTED != ret
        && OB_SIZE_OVERFLOW != ret) {
      LOG_WARN("failed to read parquet metadata", K(ret), K(real_path));
    }
  } else {
    for (int64_t i = 0; OB_SUCC(ret) && i < footer.columns_.count(); ++i) {
      const ObParquetColumnSchema &leaf = footer.columns_.at(i);
      ObFileColumnSchema one;
      ObFileValueType type = FILE_VALUE_VARCHAR;
      common::ObString name;
      if (OB_FAIL(pq_column_value_type(leaf, type))) {
        if (OB_NOT_SUPPORTED != ret) {
          LOG_WARN("failed to map parquet column", K(ret), K(i), K(leaf));
        }
      } else if (OB_FAIL(ob_write_string(alloc, leaf.name_, name))) {
        LOG_WARN("failed to copy column name", K(ret), K(i), K(leaf));
      } else if (OB_FAIL(names.push_back(name))) {
        LOG_WARN("failed to push column name", K(ret), K(name));
      } else {
        one.type_ = type;
        one.nullable_ = (PARQUET_REP_OPTIONAL == leaf.repetition_);
        one.scale_ = 0;
        if (OB_FAIL(schema.push_back(one))) {
          LOG_WARN("failed to push column schema", K(ret), K(i), K(one));
        }
      }
    }
  }
  input.close();
  return ret;
}

} // end namespace sql
} // end namespace oceanbase
