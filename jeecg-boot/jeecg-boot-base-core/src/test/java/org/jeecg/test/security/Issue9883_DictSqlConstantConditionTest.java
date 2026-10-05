package org.jeecg.test.security;

import org.jeecg.common.exception.JeecgSqlInjectionException;
import org.jeecg.common.util.SqlInjectionUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 【issues/9883】字典过滤条件中常量恒真条件（1=1）被误拦截 — 单元测试
 *
 * 问题：issues/9840 上线的「字典过滤条件 SQL 注入防护」要求比较表达式左侧必须是字段（Column），
 * 导致前端 depart.data.ts 中 "sys_position,name,id, 1=1 order by post_level asc"
 * 这类用 1=1 占位的恒真条件被判定非法，职务级别下拉框加载报错。
 *
 * 后端 SysDictServiceImpl 在条件以 ORDER BY 开头时自身会主动拼接 " 1=1 "，
 * 说明 1=1 是仓库认可的合法写法，属防护规则误伤。
 *
 * 修复：比较表达式两侧均为字面量时直接放行——不引用任何字段，不存在注入与越权风险。
 *
 * @author huanghaiwei123
 * @date 2026-10-05
 */
@ExtendWith(PrintTestResultExtension.class)
public class Issue9883_DictSqlConstantConditionTest {

    /** 非敏感表，避免触发 SensitiveTableCheckUtil 的敏感字段校验干扰断言 */
    private static final String TABLE = "sys_position";

    @Nested
    @DisplayName("常量恒真条件应放行")
    class ConstantConditionAllowed {

        @Test
        @DisplayName("纯 1=1 应放行")
        void onlyConstantCondition() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1"));
        }

        @Test
        @DisplayName("1=1 order by 应放行（前端岗位职务级别字典实际用法）")
        void constantConditionWithOrderBy() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 order by post_level asc"));
        }

        @Test
        @DisplayName("带前导空格的 1=1 order by 应放行（dictCode 按逗号切分后的真实形态）")
        void constantConditionWithLeadingSpace() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, " 1=1 order by post_level asc"));
        }

        @Test
        @DisplayName("1=1 降序排序应放行")
        void constantConditionWithOrderByDesc() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 order by post_level desc"));
        }

        @Test
        @DisplayName("1=1 与字段条件组合应放行")
        void constantConditionCombinedWithField() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 and status=1"));
        }

        @Test
        @DisplayName("常量比较其它形态（1=2、2>1、'a'='a'）应放行")
        void otherConstantComparisons() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=2"));
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "2 > 1"));
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "'a'='a'"));
        }
    }

    @Nested
    @DisplayName("合法输入回归 — 既有能力不受影响")
    class LegitimateInputRegression {

        @Test
        @DisplayName("字段与常量比较仍放行")
        void fieldEqualsLiteral() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "status=1"));
        }

        @Test
        @DisplayName("仅 ORDER BY 仍放行")
        void orderByOnly() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "order by post_level asc"));
        }

        @Test
        @DisplayName("LIKE 条件仍放行")
        void likeCondition() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "name like '%张%'"));
        }

        @Test
        @DisplayName("空值与 null 仍放行")
        void blankValue() {
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, ""));
            assertDoesNotThrow(() -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, null));
        }
    }

    @Nested
    @DisplayName("攻击向量仍拦截 — 防护不退化")
    class AttackStillBlocked {

        @Test
        @DisplayName("1=1 拼接 sleep() 时间盲注仍拦截")
        void sleepStillBlocked() {
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 and sleep(5)"));
        }

        @Test
        @DisplayName("1=1 拼接 union select 仍拦截")
        void unionSelectStillBlocked() {
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 union select password from sys_user"));
        }

        @Test
        @DisplayName("1=1 拼接 database() 仍拦截")
        void databaseFuncStillBlocked() {
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 and database()='jeecg'"));
        }

        @Test
        @DisplayName("1=1 拼接 drop table 仍拦截")
        void dropTableStillBlocked() {
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1; drop table sys_user"));
        }

        @Test
        @DisplayName("1=1 拼接 SQL 注释仍拦截")
        void sqlCommentStillBlocked() {
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1-- "));
            assertThrows(JeecgSqlInjectionException.class,
                    () -> SqlInjectionUtil.filterDictConditionSqlFromRequest(TABLE, "1=1 /*x*/"));
        }
    }
}
