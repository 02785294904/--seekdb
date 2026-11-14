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
  // A columnar file is read one page at a time, so this is what a scan may hold
  // for one column of one page. A bigger page is refused rather than buffered.
  static constexpr int64_t MAX_PAGE_LENGTH = 64 * 1024 * 1024;
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
  ObFileScanColumnDef() : is_nullable_(true), projected_(true) {}
  void reset()
  {
    column_name_.reset();
    meta_.set_null();
    is_nullable_ = true;
    projected_ = true;
  }
  TO_STRING_KV(K_(column_name), K_(meta), K_(is_nullable), K_(projected));
  common::ObString column_name_;
  common::ObObjMeta meta_;
  bool is_nullable_;
  // False when no expression of the operator reads the column, which is how a
  // columnar reader learns to leave a whole chunk of the file alone.
  bool projected_;
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
  // Copy the keys of every object of a newline delimited JSON file into names,
  // in the order they first appear, so that a caller outside the executor can
  // build the relation's column list.
  static int read_json_column_names(common::ObIAllocator &alloc,
                                    const common::ObString &real_path,
                                    common::ObIArray<common::ObString> &names);
  // Walk every object of a newline delimited JSON file and derive one schema
  // entry per named column from the values it holds; a column a record does not
  // mention counts as a null. Objects are streamed, so only the accumulators are
  // kept, and the values go through the same strict parsers a CSV scan uses.
  static int infer_json_column_types(common::ObIAllocator &alloc,
                                     const common::ObString &real_path,
                                     const common::ObIArray<common::ObString> &names,
                                     common::ObIArray<ObFileColumnSchema> &schema);
  // Read the schema a Parquet file declares in its footer: the leaf columns by
  // name and the types the format itself states. Nothing is sampled, because
  // the file says what it holds; a column this reader cannot represent stops
  // the resolve rather than becoming a guess.
  static int read_parquet_schema(common::ObIAllocator &alloc,
                                 const common::ObString &real_path,
                                 common::ObIArray<common::ObString> &names,
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
  // The allocator the file handle was opened with, which is the one a reader of
  // this file has to use for anything it keeps until the scan is closed.
  common::ObIAllocator &allocator() { return *alloc_; }
  // Rewind to the beginning and fail if the file changed since open.
  int seek_begin();
  // Reposition to an absolute offset. A columnar format keeps its metadata at
  // the end of the file and its pages wherever the footer says, so a reader of
  // one needs to land in the middle rather than walk there. The window is
  // dropped, not refilled: the next fill() reads from the new offset.
  int seek(const int64_t offset);
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

// One member of a JSON object as the reader found it. A null value carries no
// text, every other value is text: a string with its escapes decoded, anything
// else the exact bytes it occupies in the file. Classifying that text is then
// the same strict job a CSV field already has, except that a quoted string is
// always a string: a key whose value the file wrote as "01234" holds text that
// looks like a number but is not one.
struct ObJsonlMember
{
  ObJsonlMember()
    : key_(), value_(), is_null_(false), is_string_(false),
      key_off_(-1), key_len_(0), value_off_(-1), value_len_(0)
  {}
  void reset()
  {
    key_.reset();
    value_.reset();
    is_null_ = false;
    is_string_ = false;
    key_off_ = -1;
    key_len_ = 0;
    value_off_ = -1;
    value_len_ = 0;
  }
  TO_STRING_KV(K_(key), K_(value), K_(is_null), K_(is_string));
  common::ObString key_;
  common::ObString value_;
  bool is_null_;
  bool is_string_;
  // Where the two tokens sit in the reader's record buffer. The buffer grows
  // while a record is read, so a window taken from it before the growth would
  // point at memory the buffer no longer uses; a token is noted as an offset
  // and turned into a window only once the record is complete.
  int64_t key_off_;
  int64_t key_len_;
  int64_t value_off_;
  int64_t value_len_;
};

// Reader of the newline delimited JSON format: one object per record, records
// streamed a byte at a time so only the current one is ever held. Names are
// matched byte for byte, and a value that is not a scalar travels as its source
// text rather than a parsed tree.
class ObJsonlReader
{
public:
  ObJsonlReader();
  ~ObJsonlReader();
  // The reader borrows input for its whole lifetime.
  int open(ObFileInput &input);
  void close();
  // Rewind the file and restart from the first object.
  int rescan();
  // Members of the next object in the order the file lists them, or OB_ITER_END
  // once the file is drained. The strings point into the reader's own buffer and
  // stay valid until the following next_object() call.
  int next_object(common::ObIArray<ObJsonlMember> &members);
  const ObFileScanErrorPos &get_last_error_pos() const { return last_err_pos_; }
private:
  enum State
  {
    BEFORE_OBJECT = 0, // only whitespace may come before the next record
    BEFORE_NAME,       // a member name or the closing brace is expected
    IN_NAME,           // inside the quoted name of a member
    BEFORE_COLON,      // the name is read, the colon is expected
    BEFORE_VALUE,      // the value of a member is about to start
    IN_STRING_VALUE,   // inside a quoted value
    IN_PLAIN_VALUE,    // a number, true, false or null
    IN_CONTAINER,      // a nested object or array, copied as it stands
    AFTER_VALUE        // a comma or the closing brace is expected
  };
  // Where the escape machine of a quoted token stands.
  enum Escape
  {
    ESC_NONE = 0,      // the next character is literal
    ESC_CHAR,          // a backslash was read, its partner is still unread
    ESC_DIGITS         // collecting the four hexadecimal digits of a \u
  };
  int step(const char c, const int64_t byte_offset, bool &record_done, bool &retry);
  int step_string(const char c, const int64_t byte_offset, const bool is_name);
  int step_container(const char c);
  int push(const char c);
  int push_code_point(const uint32_t code_point);
  int finish_token(const bool is_name);
  int finish_plain_value(const int64_t byte_offset);
  int structural_error(const char *what, const int64_t byte_offset);
  void reset_record();
private:
  ObFileInput *input_;
  // Bytes of the object being read. A token is described by an offset into it,
  // which is why the strings handed out stay valid until the next record.
  common::ObSqlString record_buf_;
  common::ObSEArray<ObJsonlMember, 16> members_;
  State state_;
  Escape escape_;
  // Where the token currently being read begins inside record_buf_.
  int64_t token_off_;
  int64_t hex_value_;
  int64_t hex_count_;
  uint32_t high_part_;
  // A \u that named the first half of a surrogate pair waits for its partner.
  bool high_pending_;
  // Nesting level inside a container value, and whether its bytes stand inside
  // a quoted string, which may hold braces of its own.
  int64_t depth_;
  bool container_string_;
  bool container_escape_;
  int64_t line_;
  int64_t rec_start_line_;
  int64_t rec_start_off_;
  ObFileScanErrorPos last_err_pos_;
  DISALLOW_COPY_AND_ASSIGN(ObJsonlReader);
};

// Row oriented reader of one newline delimited JSON file. A record fills the row
// by name: a column whose key the object does not mention becomes null, and a
// key the relation has no column for is left out, which is what lets records of
// different shapes share one relation.
class ObJsonlScanner : public ObFileScanner
{
public:
  ObJsonlScanner();
  virtual ~ObJsonlScanner();
  virtual int open(ObFileInput &input,
                   const common::ObIArray<ObFileScanColumnDef> &columns) override;
  virtual int next_row(common::ObIArray<common::ObString> &row) override;
  virtual int rescan() override;
  virtual void close() override;
  // Indices into names listed in name order, built by inserting one position at
  // a time so the caller needs no sorting of its own.
  static int build_name_order(const common::ObIArray<common::ObString> &names,
                              common::ObIArray<int64_t> &order);
  // Where key belongs among names, matched byte for byte, or -1 for a key no
  // column was built for.
  static int find_name(const common::ObIArray<common::ObString> &names,
                       const common::ObIArray<int64_t> &order,
                       const common::ObString &key,
                       int64_t &slot);
private:
  ObFileInput *input_;
  const common::ObIArray<ObFileScanColumnDef> *columns_;
  // The name of each column, and the columns listed by it. A record is laid out
  // by key, so the key of every member has to find its column.
  common::ObSEArray<common::ObString, 16> names_;
  common::ObSEArray<int64_t, 16> name_order_;
  ObJsonlReader reader_;
  DISALLOW_COPY_AND_ASSIGN(ObJsonlScanner);
};

// The numbers below are the ones the Parquet format writes into its metadata.
// They are listed as the format names them, so a reader of this file can check
// a value against the specification without translating through a local order.
enum ObParquetPhysicalType
{
  PARQUET_TYPE_BOOLEAN = 0,
  PARQUET_TYPE_INT32 = 1,
  PARQUET_TYPE_INT64 = 2,
  PARQUET_TYPE_INT96 = 3,
  PARQUET_TYPE_FLOAT = 4,
  PARQUET_TYPE_DOUBLE = 5,
  PARQUET_TYPE_BYTE_ARRAY = 6,
  PARQUET_TYPE_FIXED_LEN_BYTE_ARRAY = 7
};

enum ObParquetRepetition
{
  PARQUET_REP_REQUIRED = 0,
  PARQUET_REP_OPTIONAL = 1,
  PARQUET_REP_REPEATED = 2
};

enum ObParquetEncoding
{
  PARQUET_ENC_PLAIN = 0,
  PARQUET_ENC_PLAIN_DICTIONARY = 2,
  PARQUET_ENC_RLE = 3,
  PARQUET_ENC_BIT_PACKED = 4,
  PARQUET_ENC_RLE_DICTIONARY = 8
};

// The converted (logical) type a column may be annotated with, numbered as the
// format numbers them. Only these are representable by one of the file value
// types; a decimal, a date or a timestamp annotation stops the resolve instead
// of becoming a guess, because the number under the annotation is not the value
// SQL would have to show. PARQUET_CONV_NONE stands for the field being absent,
// which is how most writers leave a plain integer or string column.
enum ObParquetConvertedType
{
  PARQUET_CONV_NONE = -1,
  PARQUET_CONV_UTF8 = 0,
  PARQUET_CONV_MAP = 1,
  PARQUET_CONV_LIST = 3,
  PARQUET_CONV_ENUM = 4,
  PARQUET_CONV_DECIMAL = 5,
  PARQUET_CONV_DATE = 6,
  PARQUET_CONV_TIME_MILLIS = 7,
  PARQUET_CONV_TIME_MICROS = 8,
  PARQUET_CONV_TIMESTAMP_MILLIS = 9,
  PARQUET_CONV_TIMESTAMP_MICROS = 10,
  PARQUET_CONV_UINT_8 = 11,
  PARQUET_CONV_UINT_16 = 12,
  PARQUET_CONV_UINT_32 = 13,
  PARQUET_CONV_UINT_64 = 14,
  PARQUET_CONV_INT_8 = 15,
  PARQUET_CONV_INT_16 = 16,
  PARQUET_CONV_INT_32 = 17,
  PARQUET_CONV_INT_64 = 18,
  PARQUET_CONV_JSON = 19,
  PARQUET_CONV_BSON = 20
};

enum ObParquetCodec
{
  PARQUET_CODEC_UNCOMPRESSED = 0,
  PARQUET_CODEC_SNAPPY = 1
};

enum ObParquetPageType
{
  PARQUET_PAGE_DATA = 0,
  PARQUET_PAGE_INDEX = 1,
  PARQUET_PAGE_DICTIONARY = 2,
  PARQUET_PAGE_DATA_V2 = 3
};

// Reader for the thrift compact protocol the Parquet metadata is written in. It
// decodes the fields a scan needs and skips every field it does not, so a file
// from a newer library still reads as long as the fields that matter stay inside
// this subset. A field id is the id before it in the same struct plus the delta
// in its header, so each struct keeps its own previous id and nesting needs no
// further state.
class ObThriftCompactReader
{
public:
  ObThriftCompactReader() : buf_(NULL), len_(0), pos_(0) {}
  void init(const char *buf, const int64_t len, const int64_t pos)
  {
    buf_ = buf;
    len_ = len;
    pos_ = pos;
  }
  int64_t pos() const { return pos_; }
  // OB_ITER_END once the stop byte of the current struct is reached.
  int next_field(int64_t &prev_id, int64_t &field_id, int8_t &type);
  int read_i32(int32_t &value);
  int read_i64(int64_t &value);
  // The standalone boolean, one byte. A boolean field of a struct carries its
  // value in the type next_field() reports and must not be read here.
  int read_bool(bool &value);
  int read_double(double &value);
  // The bytes of a binary field, which stay inside the buffer being read.
  int read_binary(common::ObString &value);
  int read_list_header(int8_t &elem_type, int64_t &count);
  // Consume one value of the type the field header said, however deep it is.
  // OB_SIZE_OVERFLOW means the buffer ran out, which a caller may answer by
  // reading a longer buffer.
  int skip(int8_t type);
  TO_STRING_KV(K_(pos), K_(len));
private:
  int read_u8(uint8_t &value);
  int read_varint(uint64_t &value);
  // The recursion behind skip(), carrying how deep the value nests so a
  // malformed metadata block cannot drive the stack down indefinitely.
  int skip_value(const int8_t type, const int64_t depth);
  int skip_struct(const int64_t depth);
  const char *buf_;
  int64_t len_;
  int64_t pos_;
  DISALLOW_COPY_AND_ASSIGN(ObThriftCompactReader);
};

// One leaf column of a Parquet file as its footer describes it. Only a flat
// schema is representable here: a column nested inside a group carries the
// repetition levels of a tree, which this reader refuses instead of guessing at.
struct ObParquetColumnSchema
{
  ObParquetColumnSchema()
    : name_(), physical_type_(PARQUET_TYPE_INT32),
      converted_type_(PARQUET_CONV_NONE), repetition_(PARQUET_REP_REQUIRED),
      type_length_(0), num_children_(0)
  {}
  void reset()
  {
    name_.reset();
    physical_type_ = PARQUET_TYPE_INT32;
    converted_type_ = PARQUET_CONV_NONE;
    repetition_ = PARQUET_REP_REQUIRED;
    type_length_ = 0;
    num_children_ = 0;
  }
  TO_STRING_KV(K_(name), K_(physical_type), K_(converted_type),
               K_(repetition), K_(type_length), K_(num_children));
  common::ObString name_;
  int64_t physical_type_;
  // The logical type the writer annotated the column with, kept so an encoding
  // this reader cannot represent is named rather than silently reshaped.
  int64_t converted_type_;
  int64_t repetition_;
  int64_t type_length_;
  int64_t num_children_;
};

// Where one column's pages start inside one row group.
struct ObParquetChunkLocation
{
  ObParquetChunkLocation()
    : column_index_(-1), data_page_offset_(0), dictionary_page_offset_(-1),
      total_compressed_size_(0), num_values_(0), codec_(PARQUET_CODEC_UNCOMPRESSED), path_name_()
  {}
  void reset()
  {
    column_index_ = -1;
    data_page_offset_ = 0;
    dictionary_page_offset_ = -1;
    total_compressed_size_ = 0;
    num_values_ = 0;
    codec_ = PARQUET_CODEC_UNCOMPRESSED;
    path_name_.reset();
  }
  TO_STRING_KV(K_(column_index), K_(data_page_offset), K_(dictionary_page_offset),
               K_(total_compressed_size), K_(num_values), K_(codec), K_(path_name));
  int64_t column_index_;
  int64_t data_page_offset_;
  // -1 unless the column is dictionary encoded, whose values live in a page of
  // their own ahead of the data pages.
  int64_t dictionary_page_offset_;
  // Every page of the chunk, header included, so the first page plus this is
  // where the column stops: what lies behind it belongs to the file and is not
  // a page, however much a writer leaves something there.
  int64_t total_compressed_size_;
  int64_t num_values_;
  int64_t codec_;
  // The one name the path of the chunk in the schema holds, which is checked
  // against the name of the column it is matched to: row groups whose chunks
  // are out of step with the schema would otherwise hand the pages of one
  // column to another.
  common::ObString path_name_;
};

struct ObParquetRowGroup
{
  ObParquetRowGroup() : num_rows_(0), chunks_() {}
  void reset()
  {
    num_rows_ = 0;
    chunks_.reuse();
  }
  TO_STRING_KV(K_(num_rows), K_(chunks));
  int64_t num_rows_;
  common::ObSEArray<ObParquetChunkLocation, 8> chunks_;
};

// What a scan needs from the footer: the row count, the leaf columns and the
// page addresses of every row group.
struct ObParquetFooter
{
  ObParquetFooter() : num_rows_(0), data_end_(0), columns_(), row_groups_() {}
  void reset()
  {
    num_rows_ = 0;
    data_end_ = 0;
    columns_.reuse();
    row_groups_.reuse();
  }
  TO_STRING_KV(K_(num_rows), K_(data_end), K_(columns), K_(row_groups));
  int64_t num_rows_;
  // one past the last byte a page can occupy, which is where the metadata block
  // of the file begins
  int64_t data_end_;
  common::ObSEArray<ObParquetColumnSchema, 16> columns_;
  common::ObSEArray<ObParquetRowGroup, 4> row_groups_;
};

// One value of a decoded page. The text lives in the buffer of the column that
// produced it and stays valid until that column reads its next page.
struct ObParquetCell
{
  ObParquetCell() : off_(0), len_(0), is_null_(false) {}
  void reset() { off_ = 0; len_ = 0; is_null_ = false; }
  TO_STRING_KV(K_(off), K_(len), K_(is_null));
  int64_t off_;
  int64_t len_;
  bool is_null_;
};

// What a scan needs from one page header. The two page versions state their
// counts differently: a v1 page counts every row, nulls included, and carries
// the levels inside the compressed block, while a v2 page counts the values it
// actually stores, names the rows separately and keeps the levels in front of
// the block, uncompressed. The fields that do not apply keep their default.
struct ObParquetPageHeader
{
  ObParquetPageHeader()
    : page_type_(PARQUET_PAGE_DATA), encoding_(PARQUET_ENC_PLAIN),
      uncompressed_size_(0), compressed_size_(0), num_values_(0), num_rows_(0),
      num_nulls_(0), def_level_bytes_(0), rep_level_bytes_(0),
      def_level_encoding_(PARQUET_ENC_RLE), rep_level_encoding_(PARQUET_ENC_RLE),
      is_compressed_(true), header_length_(0)
  {}
  void reset()
  {
    page_type_ = PARQUET_PAGE_DATA;
    encoding_ = PARQUET_ENC_PLAIN;
    uncompressed_size_ = 0;
    compressed_size_ = 0;
    num_values_ = 0;
    num_rows_ = 0;
    num_nulls_ = 0;
    def_level_bytes_ = 0;
    rep_level_bytes_ = 0;
    def_level_encoding_ = PARQUET_ENC_RLE;
    rep_level_encoding_ = PARQUET_ENC_RLE;
    is_compressed_ = true;
    header_length_ = 0;
  }
  TO_STRING_KV(K_(page_type), K_(encoding), K_(uncompressed_size),
               K_(compressed_size), K_(num_values), K_(num_rows), K_(num_nulls),
               K_(def_level_bytes), K_(rep_level_bytes), K_(def_level_encoding),
               K_(rep_level_encoding), K_(is_compressed), K_(header_length));
  int64_t page_type_;
  int64_t encoding_;
  int64_t uncompressed_size_;
  int64_t compressed_size_;
  int64_t num_values_;
  int64_t num_rows_;
  int64_t num_nulls_;
  // only a v2 data page states these; a v1 page prefixes each block with its
  // bit width inside the decompressed bytes instead
  int64_t def_level_bytes_;
  int64_t rep_level_bytes_;
  // how a version 1 page encoded its levels, which decides whether a block
  // starts with a bit width byte; a version 2 page always uses RLE
  int64_t def_level_encoding_;
  int64_t rep_level_encoding_;
  bool is_compressed_;
  // bytes the header itself took, so the body starts right after it
  int64_t header_length_;
};

// Streaming reader of the Parquet format. The footer is read once and pages are
// then read one column at a time, so what is held in memory follows the size of
// a page rather than the size of the file. Rows leave as text exactly like the
// CSV and JSON scanners, and are typed by the same strict parsers, so a column
// can never be typed by one rule and converted by another.
class ObParquetScanner : public ObFileScanner
{
public:
  ObParquetScanner();
  virtual ~ObParquetScanner();
  virtual int open(ObFileInput &input,
                   const common::ObIArray<ObFileScanColumnDef> &columns) override;
  virtual int next_row(common::ObIArray<common::ObString> &row) override;
  virtual int rescan() override;
  virtual void close() override;
private:
  // The page a column is handing rows from, and where its next page is. One of
  // these exists per requested column for as long as the scanner is open; they
  // are allocated one by one because a page buffer cannot be copied.
  struct ColumnState
  {
    ColumnState()
      : chunk_(NULL), schema_(NULL), max_def_level_(0), text_(), cells_(),
        dict_text_(), dict_(),
        next_page_offset_(0), chunk_end_(0), page_first_row_(0), page_row_count_(0),
        values_read_(0), rows_read_(0)
    {}
    void reset_page()
    {
      text_.reset();
      cells_.reuse();
      page_first_row_ = 0;
      page_row_count_ = 0;
    }
    TO_STRING_KV(K_(next_page_offset), K_(chunk_end), K_(page_first_row), K_(page_row_count),
                 K_(values_read), K_(rows_read), K_(max_def_level));
    const ObParquetChunkLocation *chunk_;
    // What the footer says about the column, kept so a page of it is decoded by
    // the very rules its type was derived from.
    const ObParquetColumnSchema *schema_;
    // The deepest definition level a flat schema reaches is the column's own: 1
    // when it may hold a null and 0 when it may not.
    int64_t max_def_level_;
    ObSqlString text_;
    common::ObSEArray<ObParquetCell, 8> cells_;
    ObSqlString dict_text_;
    common::ObSEArray<ObParquetCell, 8> dict_;
    int64_t next_page_offset_;
    // one past the last byte of the pages this column has in the row group, so
    // whatever a writer left between them and the metadata is never mistaken
    // for another page
    int64_t chunk_end_;
    int64_t page_first_row_;
    int64_t page_row_count_;
    // how many values and rows of the column chunk have been decoded, which is
    // what tells a scan that a column is done
    int64_t values_read_;
    int64_t rows_read_;
  };

  int read_at(const int64_t offset, const int64_t len, ObSqlString &out);
  int load_footer();
  // The current row group's chunks are matched to the requested columns, and
  // every column starts again at its first page, so a column no expression
  // names is never read at all.
  int start_row_group();
  // Decode enough pages of one column that the given row of the row group has
  // a cell.
  int ensure_page(ColumnState &state, const int64_t row);
  // Read and decode the page state.next_page_offset_ points at, appending its
  // cells and moving the offset to the page after it.
  int load_page(ColumnState &state);
  // Read the header at offset and then the body it describes. A header is not
  // length prefixed, so the buffer is read tentatively and grown once more if
  // the parse ran out of it.
  int read_page(const int64_t offset, ObParquetPageHeader &info, ObSqlString &body);
  int parse_page_header(const char *buf, const int64_t buf_len,
                        ObParquetPageHeader &info);
  // The levels of one page as one count per row. A layout this reader does not
  // know stops the scan instead of guessing at it; consumed reports how many
  // bytes the block took, which is how the values of a version 1 page are found.
  int decode_levels(const char *src, const int64_t src_len, const int64_t bit_width,
                    const int64_t count, common::ObIArray<int64_t> &levels,
                    int64_t &consumed);
  int decode_dictionary(ColumnState &state, const ObParquetPageHeader &info,
                        const char *body, const int64_t body_len);
  int decode_values(ColumnState &state, const ObParquetPageHeader &info,
                    const char *body, const int64_t body_len);
  // Cells for row_count rows of one page. def_levels holds a level per row when
  // the column is optional and is not read at all when it cannot be null.
  int format_plain(const ObParquetColumnSchema &schema, ObSqlString &text,
                   common::ObIArray<ObParquetCell> &cells,
                   const char *values, const int64_t values_len,
                   const common::ObIArray<int64_t> &def_levels,
                   const int64_t max_def_level, const int64_t row_count);
  // A dictionary encoded page holds one index per value, and every index names
  // an entry the dictionary page already turned into text, so the values of the
  // column are copied rather than decoded again.
  int format_dictionary(ColumnState &state,
                        const char *index_bytes, const int64_t index_len,
                        const common::ObIArray<int64_t> &def_levels,
                        const int64_t max_def_level, const int64_t row_count);
  // One value of the column's physical type, read at pos and appended as text.
  // For a boolean, pos counts bits instead of bytes, because the format packs
  // eight of them into a byte.
  int read_value(const ObParquetColumnSchema &schema, ObSqlString &text,
                 const char *src, const int64_t src_len, int64_t &pos,
                 ObParquetCell &cell);
  // Text of one decoded value, appended to the buffer the cells index.
  int append_number(ObSqlString &text, const int64_t value, ObParquetCell &cell);
  int append_double(ObSqlString &text, const double value, ObParquetCell &cell);
  int append_bool(ObSqlString &text, const bool value, ObParquetCell &cell);
  int append_text(ObSqlString &text, const char *value, const int64_t len,
                  ObParquetCell &cell);

  ObFileInput *input_;
  common::ObIAllocator *alloc_;
  const common::ObIArray<ObFileScanColumnDef> *columns_;
  ObParquetFooter footer_;
  // The metadata block read out of the end of the file. The column names the
  // footer holds point into it, so it lives as long as the scan does; it is the
  // descriptor of the file rather than its rows, and is bounded by MAX_PAGE_LENGTH.
  ObSqlString meta_;
  common::ObSEArray<ColumnState *, 16> states_;
  int64_t row_group_index_;
  int64_t row_in_group_;
  int64_t group_rows_;
  bool started_;
  DISALLOW_COPY_AND_ASSIGN(ObParquetScanner);
};

} // end namespace sql
} // end namespace oceanbase

#endif /* OCEANBASE_BASIC_OB_FILE_SCAN_UTILS_H_ */
