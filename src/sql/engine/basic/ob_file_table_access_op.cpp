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

#define USING_LOG_PREFIX SQL_ENG

#include "sql/engine/basic/ob_file_table_access_op.h"
#include "sql/engine/ob_exec_context.h"

namespace oceanbase
{
using namespace common;
namespace sql
{
OB_SERIALIZE_MEMBER_INHERIT(ObFileTableAccessSpec,
                            ObOpSpec,
                            kind_,
                            is_glob_,
                            with_header_,
                            delimiter_,
                            quote_,
                            escape_,
                            has_nullstr_,
                            nullstr_,
                            raw_path_,
                            real_paths_,
                            column_names_,
                            column_exprs_);

ObFileTableAccessOp::ObFileTableAccessOp(ObExecContext &exec_ctx,
                                         const ObOpSpec &spec,
                                         ObOpInput *input)
  : ObOperator(exec_ctx, spec, input),
    file_alloc_(),
    column_defs_(),
    file_input_(),
    csv_scanner_(),
    json_scanner_(),
    scan_ready_(false),
    file_idx_(0)
{
}

int ObFileTableAccessOp::prepare_scan()
{
  int ret = OB_SUCCESS;
  const bool by_name = (FILE_TABLE_JSON == MY_SPEC.kind_);
  column_defs_.reuse();
  if (by_name && MY_SPEC.column_names_.count() != MY_SPEC.column_exprs_.count()) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("json column has no name to match", K(ret), "name_cnt",
             MY_SPEC.column_names_.count(), "col_cnt", MY_SPEC.column_exprs_.count());
  }
  for (int64_t i = 0; OB_SUCC(ret) && i < MY_SPEC.column_exprs_.count(); ++i) {
    ObFileScanColumnDef def;
    ObExpr *expr = MY_SPEC.column_exprs_.at(i);
    // the width of a record is all the scanner needs, the types belong to the
    // expressions the values are written into
    def.meta_.set_type(OB_ISNULL(expr) ? ObVarcharType : expr->datum_meta_.type_);
    def.meta_.set_collation_type(CS_TYPE_UTF8MB4_GENERAL_CI);
    def.is_nullable_ = true;
    if (by_name) {
      // a value finds its column through the key the file writes it under
      def.column_name_ = MY_SPEC.column_names_.at(i);
    }
    if (OB_FAIL(column_defs_.push_back(def))) {
      LOG_WARN("failed to push column def", K(ret), K(i));
    }
  }
  if (OB_SUCC(ret)) {
    ObCsvScanOptions options;
    options.delimiter_ = MY_SPEC.delimiter_;
    options.quote_ = MY_SPEC.quote_;
    options.escape_ = MY_SPEC.escape_;
    options.has_nullstr_ = MY_SPEC.has_nullstr_;
    options.nullstr_ = MY_SPEC.nullstr_;
    csv_scanner_.set_options(options);
    csv_scanner_.set_with_header(MY_SPEC.with_header_);
  }
  return ret;
}

ObFileScanner *ObFileTableAccessOp::cur_scanner()
{
  ObFileScanner *scanner = NULL;
  if (FILE_TABLE_JSON == MY_SPEC.kind_) {
    scanner = &json_scanner_;
  } else {
    scanner = &csv_scanner_;
  }
  return scanner;
}

int ObFileTableAccessOp::open_current_file()
{
  int ret = OB_SUCCESS;
  if (OB_UNLIKELY(file_idx_ < 0 || file_idx_ >= MY_SPEC.real_paths_.count())) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("file index out of range", K(ret), K_(file_idx));
  } else if (OB_FAIL(file_input_.open(file_alloc_, MY_SPEC.real_paths_.at(file_idx_)))) {
    LOG_WARN("failed to open file", K(ret), "path", MY_SPEC.real_paths_.at(file_idx_));
  } else if (OB_FAIL(cur_scanner()->open(file_input_, column_defs_))) {
    LOG_WARN("failed to open file scanner", K(ret), "kind", MY_SPEC.kind_);
    file_input_.close();
  }
  return ret;
}

int ObFileTableAccessOp::close_current_file()
{
  int ret = OB_SUCCESS;
  csv_scanner_.close();
  json_scanner_.close();
  file_input_.close();
  file_alloc_.reset();
  return ret;
}

int ObFileTableAccessOp::inner_open()
{
  int ret = OB_SUCCESS;
  file_idx_ = 0;
  scan_ready_ = false;
  if (OB_UNLIKELY(MY_SPEC.real_paths_.empty() || MY_SPEC.column_exprs_.empty())) {
    ret = OB_ERR_UNEXPECTED;
    LOG_WARN("empty file table spec", K(ret), "path_cnt", MY_SPEC.real_paths_.count(),
             "col_cnt", MY_SPEC.column_exprs_.count());
  } else if (OB_FAIL(prepare_scan())) {
    LOG_WARN("failed to prepare scan", K(ret));
  } else if (FILE_TABLE_GLOB == MY_SPEC.kind_) {
    // glob() lists the resolved paths, the files themselves are never opened
    scan_ready_ = true;
  } else if (FILE_TABLE_CSV != MY_SPEC.kind_ && FILE_TABLE_JSON != MY_SPEC.kind_) {
    ret = OB_NOT_SUPPORTED;
    LOG_USER_ERROR(OB_NOT_SUPPORTED, "file format of the file table function");
    LOG_WARN("unsupported file table kind", K(ret), "kind", MY_SPEC.kind_);
  } else if (OB_FAIL(open_current_file())) {
    LOG_WARN("failed to open first file", K(ret));
  } else {
    scan_ready_ = true;
  }
  return ret;
}

int ObFileTableAccessOp::inner_rescan()
{
  int ret = OB_SUCCESS;
  file_idx_ = 0;
  if (OB_FAIL(ObOperator::inner_rescan())) {
    LOG_WARN("failed to rescan operator", K(ret));
  } else if (FILE_TABLE_GLOB != MY_SPEC.kind_) {
    if (OB_FAIL(close_current_file())) {
      LOG_WARN("failed to close file", K(ret));
    } else if (OB_FAIL(open_current_file())) {
      LOG_WARN("failed to reopen file", K(ret));
    }
  }
  return ret;
}

int ObFileTableAccessOp::switch_iterator()
{
  // A file list is iterated once per rescan, so like the other table functions
  // this answers "any further iterator?" with OB_ITER_END. The list is still
  // rewound here, so whoever rescans afterwards sees the first file again.
  int ret = OB_SUCCESS;
  file_idx_ = 0;
  if (FILE_TABLE_GLOB != MY_SPEC.kind_) {
    if (OB_FAIL(close_current_file())) {
      LOG_WARN("failed to close file", K(ret));
    } else if (OB_FAIL(open_current_file())) {
      LOG_WARN("failed to reopen file", K(ret));
    }
  }
  if (OB_FAIL(ret)) {
  } else {
    clear_batch_end_flag();
    ret = OB_ITER_END;
  }
  return ret;
}

// Hand out the next record. For a table read out of the file's own contents the
// reader walks the resolved file list in order; for glob() the list is the result.
int ObFileTableAccessOp::next_record(common::ObIArray<common::ObString> &row)
{
  int ret = OB_SUCCESS;
  row.reuse();
  if (!scan_ready_) {
    ret = OB_NOT_INIT;
    LOG_WARN("file scan is not opened", K(ret));
  } else if (FILE_TABLE_GLOB == MY_SPEC.kind_) {
    if (file_idx_ >= MY_SPEC.real_paths_.count()) {
      ret = OB_ITER_END;
    } else if (OB_FAIL(row.push_back(MY_SPEC.real_paths_.at(file_idx_)))) {
      LOG_WARN("failed to push file name", K(ret), K_(file_idx));
    } else {
      ++file_idx_;
    }
  } else if (file_idx_ >= MY_SPEC.real_paths_.count()) {
    // the whole list has been scanned; asking again must not touch the scanner,
    // whose current file is already closed
    ret = OB_ITER_END;
  } else {
    bool got = false;
    while (OB_SUCC(ret) && !got) {
      row.reuse();
      if (OB_FAIL(cur_scanner()->next_row(row))) {
        if (OB_ITER_END != ret) {
          LOG_WARN("failed to read file record", K(ret), K_(file_idx), "kind", MY_SPEC.kind_);
        } else if (OB_FAIL(close_current_file())) {
          LOG_WARN("failed to close file", K(ret), K_(file_idx));
        } else {
          ++file_idx_;
          if (file_idx_ >= MY_SPEC.real_paths_.count()) {
            ret = OB_ITER_END;
          } else if (OB_FAIL(open_current_file())) {
            LOG_WARN("failed to open next file", K(ret), K_(file_idx));
          }
        }
      } else {
        got = true;
      }
    }
  }
  return ret;
}

int ObFileTableAccessOp::write_row(const common::ObIArray<common::ObString> &row)
{
  int ret = OB_SUCCESS;
  const int64_t col_cnt = MY_SPEC.column_exprs_.count();
  for (int64_t i = 0; OB_SUCC(ret) && i < col_cnt; ++i) {
    ObExpr *expr = MY_SPEC.column_exprs_.at(i);
    if (OB_ISNULL(expr)) {
      // a column the query does not read; the field is still parsed, because the
      // reader has to walk past it to reach the ones behind it, but nothing is
      // converted or copied for it
    } else {
      // no reset(): locate_datum_for_write points ptr_ at the reserved result
      // buffer of this slot, and ObDatum has no inline storage to fall back on
      ObDatum &dst = expr->locate_datum_for_write(eval_ctx_);
      if (i >= row.count() || OB_ISNULL(row.at(i).ptr())) {
        dst.set_null();
      } else if (OB_FAIL(write_value(*expr, row.at(i), dst))) {
        if (OB_INVALID_ARGUMENT != ret) {
          LOG_WARN("failed to write field value", K(ret), K(i));
        }
      }
      if (OB_SUCC(ret)) {
        // the value is in the datum now, so both the shared state and the slot
        // of this batch count as evaluated
        expr->set_evaluated_projected(eval_ctx_);
        expr->set_evaluated_flag(eval_ctx_);
      }
    }
  }
  return ret;
}

// The name a column's inferred type is shown under, matching DESCRIBE.
static const char *inferred_type_name(const ObObjType type)
{
  const char *name = "VARCHAR";
  switch (type) {
  case ObTinyIntType: name = "BOOLEAN"; break;
  case ObIntType: name = "BIGINT"; break;
  case ObDoubleType: name = "DOUBLE"; break;
  case ObDateType: name = "DATE"; break;
  case ObDateTimeType: name = "DATETIME"; break;
  default: break;
  }
  return name;
}

// A column reads as the type the schema inference gave it, and the value is
// converted by the very parsers that decision was made with. When a value no
// longer fits, the file changed after the statement was resolved, so the scan
// stops with an error rather than handing out a row nobody asked for.
int ObFileTableAccessOp::write_value(ObExpr &expr,
                                     const common::ObString &text,
                                     common::ObDatum &dst)
{
  int ret = OB_SUCCESS;
  bool matched = false;
  const ObObjType type = expr.datum_meta_.type_;
  switch (type) {
  case ObTinyIntType: {
    int64_t value = 0;
    matched = ObFileValueParser::parse_boolean(text, value);
    if (matched) { dst.set_int(value); }
    break;
  }
  case ObIntType: {
    int64_t value = 0;
    matched = ObFileValueParser::parse_bigint(text, value);
    if (matched) { dst.set_int(value); }
    break;
  }
  case ObDoubleType: {
    double value = 0;
    matched = ObFileValueParser::parse_double(text, value);
    if (matched) { dst.set_double(value); }
    break;
  }
  case ObDateType: {
    int32_t value = 0;
    matched = ObFileValueParser::parse_date(text, value);
    if (matched) { dst.set_date(value); }
    break;
  }
  case ObDateTimeType: {
    int64_t value = 0;
    int8_t scale = 0;
    matched = ObFileValueParser::parse_datetime(text, value, scale);
    if (matched) { dst.set_datetime(value); }
    break;
  }
  default: {
    ObDatum src;
    src.set_string(text);
    ObExprStrResAlloc res_alloc(expr, eval_ctx_);
    matched = true;
    if (OB_FAIL(dst.deep_copy(src, res_alloc))) {
      LOG_WARN("failed to copy field value", K(ret), K(type));
    }
    break;
  }
  }
  if (OB_SUCC(ret) && !matched) {
    ret = OB_INVALID_ARGUMENT;
    const ObFileScanErrorPos &pos = cur_scanner()->get_last_error_pos();
    ObSqlString msg;
    if (OB_FAIL(msg.append_fmt("value does not fit the inferred column type %s"
                               " at line %ld, byte offset %ld",
                               inferred_type_name(type), pos.line_, pos.byte_offset_))) {
      LOG_WARN("failed to build error message", K(ret));
    } else {
      LOG_USER_ERROR(OB_INVALID_ARGUMENT, msg.ptr());
      LOG_WARN("file value does not fit inferred type", K(ret), K(type), K(text), K(pos));
    }
  }
  return ret;
}

int ObFileTableAccessOp::inner_get_next_row()
{
  int ret = OB_SUCCESS;
  ObSEArray<ObString, 16> row;
  if (OB_FAIL(try_check_status())) {
    LOG_WARN("failed to check status", K(ret));
  } else if (OB_FAIL(next_record(row))) {
    if (OB_ITER_END != ret) {
      LOG_WARN("failed to read next record", K(ret));
    }
  } else {
    clear_evaluated_flag();
    if (OB_FAIL(write_row(row))) {
      LOG_WARN("failed to write row", K(ret));
    }
  }
  return ret;
}

int ObFileTableAccessOp::inner_get_next_batch(const int64_t max_row_cnt)
{
  int ret = OB_SUCCESS;
  const int64_t batch_size = std::min(max_row_cnt, MY_SPEC.max_batch_size_);
  brs_.size_ = 0;
  brs_.end_ = false;
  if (OB_FAIL(try_check_status())) {
    LOG_WARN("failed to check status", K(ret));
  } else {
    clear_evaluated_flag();
    ObEvalCtx::BatchInfoScopeGuard guard(eval_ctx_);
    guard.set_batch_size(batch_size);
    ObSEArray<ObString, 16> row;
    for (int64_t i = 0; OB_SUCC(ret) && i < batch_size; ++i) {
      guard.set_batch_idx(i);
      row.reuse();
      if (OB_FAIL(next_record(row))) {
        if (OB_ITER_END != ret) {
          LOG_WARN("failed to read next record", K(ret), K(i));
        }
      } else if (OB_FAIL(write_row(row))) {
        LOG_WARN("failed to write row", K(ret), K(i));
      } else {
        ++brs_.size_;
      }
    }
    if (OB_ITER_END == ret) {
      ret = OB_SUCCESS;
    }
    if (OB_SUCC(ret) && brs_.size_ <= 0) {
      // the scan itself never drops a row, so an empty batch can only mean the
      // files are exhausted
      brs_.end_ = true;
    }
  }
  return ret;
}

int ObFileTableAccessOp::inner_close()
{
  int ret = OB_SUCCESS;
  scan_ready_ = false;
  file_idx_ = 0;
  if (OB_FAIL(close_current_file())) {
    LOG_WARN("failed to close file", K(ret));
  }
  column_defs_.reuse();
  return ret;
}

void ObFileTableAccessOp::destroy()
{
  csv_scanner_.close();
  json_scanner_.close();
  file_input_.close();
  file_alloc_.reset();
  scan_ready_ = false;
  ObOperator::destroy();
}

} // end namespace sql
} // end namespace oceanbase
