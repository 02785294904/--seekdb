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

#ifndef OCEANBASE_SQL_ENGINE_BASIC_OB_FILE_TABLE_ACCESS_OP_
#define OCEANBASE_SQL_ENGINE_BASIC_OB_FILE_TABLE_ACCESS_OP_

#include "sql/engine/ob_operator.h"
#include "sql/engine/basic/ob_file_scan_utils.h"

namespace oceanbase
{
namespace sql
{
class ObFileTableAccessSpec : public ObOpSpec
{
  OB_UNIS_VERSION_V(1);
public:
  ObFileTableAccessSpec(common::ObIAllocator &alloc, const ObPhyOperatorType type)
    : ObOpSpec(alloc, type), kind_(FILE_TABLE_NONE), is_glob_(false), with_header_(true),
      delimiter_(','), quote_('"'), escape_('"'), has_nullstr_(false), nullstr_(),
      raw_path_(), real_paths_(alloc), column_names_(alloc), column_exprs_(alloc) {}
  INHERIT_TO_STRING_KV("op_spec", ObOpSpec, K_(kind), K_(is_glob), K_(with_header),
                       K_(delimiter), K_(quote), K_(escape), K_(has_nullstr), K_(nullstr),
                       K_(raw_path), K_(real_paths), K_(column_names));
  // FileTableKind, kept as an integer so the spec serializes like the other ops
  int32_t kind_;
  bool is_glob_;
  bool with_header_;
  // csv decoding characters, kept flat for the same reason as kind_
  char delimiter_;
  char quote_;
  char escape_;
  bool has_nullstr_;
  common::ObString nullstr_;
  common::ObString raw_path_;
  // Canonical files to scan, resolved once when the statement was resolved.
  common::ObFixedArray<common::ObString, common::ObIAllocator> real_paths_;
  // What the file calls each column, in column order. Only a format that matches
  // a value to its column by name needs it, and it holds the name from the file
  // rather than the one SQL ended up showing.
  common::ObFixedArray<common::ObString, common::ObIAllocator> column_names_;
  common::ObFixedArray<ObExpr *, common::ObIAllocator> column_exprs_;
private:
  DISALLOW_COPY_AND_ASSIGN(ObFileTableAccessSpec);
};

class ObFileTableAccessOp : public ObOperator
{
public:
  ObFileTableAccessOp(ObExecContext &exec_ctx, const ObOpSpec &spec, ObOpInput *input);
  virtual int inner_open() override;
  virtual int inner_rescan() override;
  virtual int switch_iterator() override;
  virtual int inner_get_next_row() override;
  virtual int inner_get_next_batch(const int64_t max_row_cnt) override;
  virtual int inner_close() override;
  virtual void destroy() override;
private:
  int prepare_scan();
  int open_current_file();
  int close_current_file();
  // The reader of the format this table was resolved from. Both live in the
  // operator, so no allocation happens per file.
  ObFileScanner *cur_scanner();
  int next_record(common::ObIArray<common::ObString> &row);
  int write_row(const common::ObIArray<common::ObString> &row);
  int write_value(ObExpr &expr, const common::ObString &text, common::ObDatum &dst);
private:
  common::ObArenaAllocator file_alloc_;
  common::ObSEArray<ObFileScanColumnDef, 16> column_defs_;
  ObFileInput file_input_;
  ObCsvScanner csv_scanner_;
  ObJsonlScanner json_scanner_;
  bool scan_ready_;
  int64_t file_idx_;
  DISALLOW_COPY_AND_ASSIGN(ObFileTableAccessOp);
};

} // end namespace sql
} // end namespace oceanbase
#endif
