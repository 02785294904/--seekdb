/*
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

#ifndef OCEANBASE_BASIC_OB_FILE_SCAN_UTILS_H_
#define OCEANBASE_BASIC_OB_FILE_SCAN_UTILS_H_

#include "lib/string/ob_string.h"
#include "lib/container/ob_iarray.h"
#include "lib/utility/ob_macro_utils.h"
#include "lib/utility/ob_print_utils.h"
#include "common/object/ob_object.h"

namespace oceanbase
{
namespace sql
{

// Bounds a file scan has to respect so that a single statement can neither
// exhaust memory nor produce an unusable relation.
struct ObFileScanLimits
{
  static const int64_t MAX_COLUMN_COUNT = 4096;
  static const int64_t MAX_FIELD_LENGTH = 1 * 1024 * 1024;
  static const int64_t MAX_RECORD_LENGTH = 8 * 1024 * 1024;
  static const int64_t MAX_FILE_COUNT = 1024;
  static const int64_t READ_BUF_SIZE = 64 * 1024;
};

// Where a decoding failure happened inside a file. Line and column are 1 based,
// byte offset is the absolute position of the offending byte.
struct ObFileScanErrorPos
{
  ObFileScanErrorPos() : line_(0), column_(0), byte_offset_(0) {}
  void reset() { line_ = 0; column_ = 0; byte_offset_ = 0; }
  TO_STRING_KV(K_(line), K_(column), K_(byte_offset));
  int64_t line_;
  int64_t column_;
  int64_t byte_offset_;
};

// One column the scanner has been told to produce, resolved before the first read.
struct ObFileScanColumnDef
{
  ObFileScanColumnDef() : is_nullable_(true) {}
  void reset()
  {
    column_name_.reset();
    meta_.set_null();
    is_nullable_ = true;
  }
  TO_STRING_KV(K_(column_name), K_(meta), K_(is_nullable));
  common::ObString column_name_;
  common::ObObjMeta meta_;
  bool is_nullable_;
};

class ObFileScanUtils
{
public:
  // Canonicalize raw_path with realpath, require the target to stay inside
  // secure_file_priv and to be a regular file. On success real_path points into
  // buf, which the caller owns.
  static int resolve_and_check_path(const common::ObString &raw_path,
                                    const common::ObString &secure_file_priv,
                                    const bool skip_priv_check,
                                    char *buf,
                                    const int64_t buf_len,
                                    common::ObString &real_path);
  static int check_file_count(const int64_t match_count);
  static int check_column_count(const int64_t column_count);
private:
  DISALLOW_COPY_AND_ASSIGN(ObFileScanUtils);
};

// Read only, streaming handle of one file. Only a fixed window is kept in
// memory and the file identity is revalidated on rewind, so a scan can neither
// mutate its input nor silently change underneath a rescan.
class ObFileInput
{
public:
  ObFileInput();
  ~ObFileInput();
  int open(common::ObIAllocator &alloc, const common::ObString &real_path);
  void close();
  bool is_opened() const { return fd_ >= 0; }
  // Move the unread tail to the head of the window and read once more.
  // Returns OB_ITER_END once the window is empty at end of file.
  int fill();
  bool is_eof() const { return eof_; }
  common::ObString buffered() const
  {
    return common::ObString(data_len_ - pos_, buf_ + pos_);
  }
  void consume(const int64_t len) { pos_ += len; }
  // Absolute position of the first buffered byte.
  int64_t logical_pos() const { return read_off_ - (data_len_ - pos_); }
  int64_t file_size() const { return size_; }
  // Rewind to the beginning and fail if the file changed since open.
  int seek_begin();
  TO_STRING_KV(K_(fd), K_(file_path), K_(size), K_(read_off), K_(data_len), K_(pos), K_(eof));
private:
  int check_fingerprint() const;
private:
  int fd_;
  common::ObString file_path_;
  char *buf_;
  char *path_buf_;
  int64_t buf_alloc_;
  int64_t data_len_;
  int64_t pos_;
  int64_t read_off_;
  int64_t size_;
  int64_t mtime_;
  int64_t dev_;
  int64_t ino_;
  bool eof_;
  common::ObIAllocator *alloc_;
  DISALLOW_COPY_AND_ASSIGN(ObFileInput);
};

// Row oriented reader over one opened file, implemented once per format.
class ObFileScanner
{
public:
  ObFileScanner() {}
  virtual ~ObFileScanner() {}
  // The scanner borrows input and columns for its whole lifetime.
  virtual int open(ObFileInput &input,
                   const common::ObIArray<ObFileScanColumnDef> &columns) = 0;
  // Append the fields of the next record; OB_ITER_END once the file is drained.
  virtual int next_row(common::ObIArray<common::ObString> &row) = 0;
  // Rewind the underlying file and restart from the first record.
  virtual int rescan() = 0;
  virtual void close() = 0;
  const ObFileScanErrorPos &get_last_error_pos() const { return last_err_pos_; }
protected:
  ObFileScanErrorPos last_err_pos_;
private:
  DISALLOW_COPY_AND_ASSIGN(ObFileScanner);
};

} // end namespace sql
} // end namespace oceanbase

#endif /* OCEANBASE_BASIC_OB_FILE_SCAN_UTILS_H_ */
