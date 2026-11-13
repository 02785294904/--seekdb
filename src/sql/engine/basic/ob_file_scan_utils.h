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
#include "lib/string/ob_sql_string.h"
#include "lib/container/ob_iarray.h"
#include "lib/container/ob_se_array.h"
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
  // constexpr so that logging a limit by reference has a symbol to link against
  static constexpr int64_t MAX_COLUMN_COUNT = 4096;
  static constexpr int64_t MAX_FIELD_LENGTH = 1 * 1024 * 1024;
  static constexpr int64_t MAX_RECORD_LENGTH = 8 * 1024 * 1024;
  static constexpr int64_t MAX_FILE_COUNT = 1024;
  static constexpr int64_t READ_BUF_SIZE = 64 * 1024;
};

// Where a decoding failure happened inside a file. Line and column are 1 based,
// column counting the field within the record, byte offset is the absolute
// position of the offending byte.
struct ObFileScanErrorPos
{
  ObFileScanErrorPos() : line_(0), column_(0), byte_offset_(0) {}
  void reset() { line_ = 0; column_ = 0; byte_offset_ = 0; }
  TO_STRING_KV(K_(line), K_(column), K_(byte_offset));
  int64_t line_;
  int64_t column_;
  int64_t byte_offset_;
};

// Parsing knobs a CSV reader was told to use. The defaults are RFC4180: comma
// separated, double quoted, "" escaping itself.
struct ObCsvScanOptions
{
  ObCsvScanOptions()
    : delimiter_(','), quote_('"'), escape_('"'), nullstr_(), has_nullstr_(false)
  {}
  void reset()
  {
    delimiter_ = ',';
    quote_ = '"';
    escape_ = '"';
    nullstr_.reset();
    has_nullstr_ = false;
  }
  TO_STRING_KV(K_(delimiter), K_(quote), K_(escape), K_(nullstr), K_(has_nullstr));
  char delimiter_;
  char quote_;
  char escape_;
  // Exact field content that means NULL; only consulted when has_nullstr_.
  common::ObString nullstr_;
  bool has_nullstr_;
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

// The types a file column may take, listed in the order a value is recognised:
// the first parser that accepts the whole field wins.
enum ObFileValueType
{
  FILE_VALUE_UNKNOWN = 0,  // no non null value seen so far
  FILE_VALUE_BOOLEAN,
  FILE_VALUE_BIGINT,
  FILE_VALUE_DOUBLE,
  FILE_VALUE_DATE,
  FILE_VALUE_DATETIME,
  FILE_VALUE_VARCHAR
};

// The schema one file column got from the values it actually holds.
struct ObFileColumnSchema
{
  ObFileColumnSchema() : type_(FILE_VALUE_UNKNOWN), nullable_(false), scale_(0) {}
  void reset()
  {
    type_ = FILE_VALUE_UNKNOWN;
    nullable_ = false;
    scale_ = 0;
  }
  TO_STRING_KV("type", static_cast<int32_t>(type_), K_(nullable), K_(scale));
  ObFileValueType type_;
  bool nullable_;
  // fractional seconds a datetime column has to keep, 0 for every other type
  int8_t scale_;
};

// Strict text to value conversion, used by the schema inference that runs while
// resolving and by the scan that runs while executing, so that a column can
// never be typed by one rule and converted by another. Every parser accepts the
// entire field only: blanks, signs that are not part of a number or leftover
// characters make the value a string.
class ObFileValueParser
{
public:
  static bool parse_boolean(const common::ObString &text, int64_t &value);
  static bool parse_bigint(const common::ObString &text, int64_t &value);
  static bool parse_double(const common::ObString &text, double &value);
  static bool parse_date(const common::ObString &text, int32_t &value);
  static bool parse_datetime(const common::ObString &text, int64_t &value, int8_t &scale);
  // Type of a single value, following the recognition order.
  static ObFileValueType recognize(const common::ObString &text);
  // Least common type of two columns; commutative by construction, and a null
  // value never changes the type it is merged into.
  static ObFileValueType merge(const ObFileValueType left, const ObFileValueType right);
  static common::ObObjType to_obj_type(const ObFileValueType type);
  static const char *type_name(const ObFileValueType type);
private:
  DISALLOW_COPY_AND_ASSIGN(ObFileValueParser);
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
  // Read the first record of a CSV file and copy the raw field bytes into
  // alloc, so that a caller outside the executor can derive the column names.
  static int read_csv_header(common::ObIAllocator &alloc,
                             const common::ObString &real_path,
                             const ObCsvScanOptions &options,
                             common::ObIArray<common::ObString> &names);
  // Walk every record of a CSV file and derive one schema entry per column from
  // the values it holds. Records are streamed, so only the accumulators are
  // kept. A malformed record is reported the same way a scan would report it.
  static int infer_csv_column_types(common::ObIAllocator &alloc,
                                    const common::ObString &real_path,
                                    const ObCsvScanOptions &options,
                                    const bool with_header,
                                    const int64_t column_count,
                                    common::ObIArray<ObFileColumnSchema> &schema);
  // True if the path contains a glob meta character.
  static bool has_wildcard(const common::ObString &pattern);
  // Like resolve_and_check_path, but the target has to be a directory. Used to
  // bound a glob pattern: only the literal directory prefix is checked.
  static int resolve_and_check_dir(const common::ObString &raw_dir,
                                   const common::ObString &secure_file_priv,
                                   const bool skip_priv_check,
                                   char *buf,
                                   const int64_t buf_len,
                                   common::ObString &real_dir);
  // Expand pattern into regular files, each one validated the same way a plain
  // file path is. Results are allocated in alloc and sorted by path.
  static int list_matching_files(common::ObIAllocator &alloc,
                                 const common::ObString &pattern,
                                 const common::ObString &secure_file_priv,
                                 const bool skip_priv_check,
                                 common::ObIArray<common::ObString> &files);
  // DESCRIBE of a query over a file table answers with this fixed shape. The
  // rows and the result metadata are both read from here so that they cannot
  // drift apart.
  static const int64_t DESCRIBE_COLUMN_COUNT = 6;
  static const char *describe_column_name(const int64_t idx);
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
  bool bom_skipped_;
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

// RFC4180 reader: one record per next_row(), records may straddle the read
// window and a quoted field may hold the delimiter, newlines and "" escapes.
class ObCsvScanner : public ObFileScanner
{
public:
  // off_ and len_ index the scanner's record buffer, so the strings handed out
  // by next_row stay valid until the following next_row() call. A missing or
  // empty unquoted field is reported as a null ObString, an empty quoted one as
  // a non null zero length ObString.
  struct Field
  {
    Field() : off_(0), len_(0), is_null_(false) {}
    TO_STRING_KV(K_(off), K_(len), K_(is_null));
    int64_t off_;
    int64_t len_;
    bool is_null_;
  };

  ObCsvScanner();
  virtual ~ObCsvScanner();
  virtual int open(ObFileInput &input,
                   const common::ObIArray<ObFileScanColumnDef> &columns) override;
  virtual int next_row(common::ObIArray<common::ObString> &row) override;
  virtual int rescan() override;
  virtual void close() override;
  void set_with_header(const bool with_header) { with_header_ = with_header; }
  // Kept for callers that only override the separator.
  void set_delimiter(const char delimiter) { options_.delimiter_ = delimiter; }
  // Quote, escape and null marker for this format; call before open(). A quote
  // that equals the escape character gives the RFC4180 "" doubling.
  void set_options(const ObCsvScanOptions &options) { options_ = options; }
  // Parse one record into fields_, which index record_buf_. Blank lines hold no
  // record and are skipped. Returns OB_ITER_END after the last record of the file.
  int next_record();

private:
  enum State
  {
    FIELD_BEGIN = 0,   // nothing of the current field consumed yet
    IN_PLAIN,          // inside an unquoted field
    IN_QUOTED,       // inside a quoted field
    QUOTE_IN_QUOTED,   // saw one quote while inside a quoted field
    AFTER_QUOTE,       // quoted field closed, skipping blanks
    AFTER_CR           // record ended on \r, a following \n belongs to it
  };
  int start_field();
  int finish_field(const bool quoted);
  int parse_one_record();
  int append_record(const char *data, const int64_t len);
  int structural_error(const char *what,
                       const int64_t line,
                       const int64_t column,
                       const int64_t byte_offset);
private:
  ObFileInput *input_;
  const common::ObIArray<ObFileScanColumnDef> *columns_;
  common::ObSqlString record_buf_;
  common::ObSEArray<Field, 16> fields_;
  ObCsvScanOptions options_;
  State state_;
  int64_t cur_off_;
  bool with_header_;
  bool header_done_;
  bool has_content_;    // current record has at least one field or partial field
  bool escape_pending_; // an escape byte was seen and its literal partner is still unread
  int64_t line_;
  // Absolute offset of the first byte of the line currently being scanned, used
  // to turn a byte offset into the 1 based column quoted in user errors.
  int64_t line_start_off_;
  // Where the record being parsed begins. A structural error is only noticed
  // once the record is complete, by which time line_ has moved past it.
  int64_t rec_start_line_;
  int64_t rec_start_off_;
  DISALLOW_COPY_AND_ASSIGN(ObCsvScanner);
};

} // end namespace sql
} // end namespace oceanbase

#endif /* OCEANBASE_BASIC_OB_FILE_SCAN_UTILS_H_ */
