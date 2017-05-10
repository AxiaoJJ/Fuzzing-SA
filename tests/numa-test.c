/*
 * NUMA configuration test cases
 *
 * Copyright (c) 2017 Red Hat Inc.
 * Authors:
 *  Igor Mammedov <imammedo@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"

static char *make_cli(const char *generic_cli, const char *test_cli)
{
    return g_strdup_printf("%s %s", generic_cli ? generic_cli : "", test_cli);
}

static char *hmp_info_numa(void)
{
    QDict *resp;
    char *s;

    resp = qmp("{ 'execute': 'human-monitor-command', 'arguments': "
                      "{ 'command-line': 'info numa '} }");
    g_assert(resp);
    g_assert(qdict_haskey(resp, "return"));
    s = g_strdup(qdict_get_str(resp, "return"));
    g_assert(s);
    QDECREF(resp);
    return s;
}

static void test_mon_explicit(const void *data)
{
    char *s;
    char *cli;

    cli = make_cli(data, "-smp 8 "
                   "-numa node,nodeid=0,cpus=0-3 "
                   "-numa node,nodeid=1,cpus=4-7 ");
    qtest_start(cli);

    s = hmp_info_numa();
    g_assert(strstr(s, "node 0 cpus: 0 1 2 3"));
    g_assert(strstr(s, "node 1 cpus: 4 5 6 7"));
    g_free(s);

    qtest_end();
    g_free(cli);
}

static void test_mon_default(const void *data)
{
    char *s;
    char *cli;

    cli = make_cli(data, "-smp 8 -numa node -numa node");
    qtest_start(cli);

    s = hmp_info_numa();
    g_assert(strstr(s, "node 0 cpus: 0 2 4 6"));
    g_assert(strstr(s, "node 1 cpus: 1 3 5 7"));
    g_free(s);

    qtest_end();
    g_free(cli);
}

static void test_mon_partial(const void *data)
{
    char *s;
    char *cli;

    cli = make_cli(data, "-smp 8 "
                   "-numa node,nodeid=0,cpus=0-1 "
                   "-numa node,nodeid=1,cpus=4-5 ");
    qtest_start(cli);

    s = hmp_info_numa();
    g_assert(strstr(s, "node 0 cpus: 0 1 2 3 6 7"));
    g_assert(strstr(s, "node 1 cpus: 4 5"));
    g_free(s);

    qtest_end();
    g_free(cli);
}

static QList *get_cpus(QDict **resp)
{
    *resp = qmp("{ 'execute': 'query-cpus' }");
    g_assert(*resp);
    g_assert(qdict_haskey(*resp, "return"));
    return  qdict_get_qlist(*resp, "return");
}

static void test_query_cpus(const void *data)
{
    char *cli;
    QDict *resp;
    QList *cpus;
    const QObject *e;

    cli = make_cli(data, "-smp 8 -numa node,cpus=0-3 -numa node,cpus=4-7");
    qtest_start(cli);
    cpus = get_cpus(&resp);
    g_assert(cpus);

    while ((e = qlist_pop(cpus))) {
        QDict *cpu, *props;
        int64_t cpu_idx, node;

        cpu = qobject_to_qdict(e);
        g_assert(qdict_haskey(cpu, "CPU"));
        g_assert(qdict_haskey(cpu, "props"));

        cpu_idx = qdict_get_int(cpu, "CPU");
        props = qdict_get_qdict(cpu, "props");
        g_assert(qdict_haskey(props, "node-id"));
        node = qdict_get_int(props, "node-id");
        if (cpu_idx >= 0 && cpu_idx < 4) {
            g_assert_cmpint(node, ==, 0);
        } else {
            g_assert_cmpint(node, ==, 1);
        }
    }

    QDECREF(resp);
    qtest_end();
    g_free(cli);
}

int main(int argc, char **argv)
{
    const char *args = NULL;
    const char *arch = qtest_get_arch();

    if (strcmp(arch, "aarch64") == 0) {
        args = "-machine virt";
    }

    g_test_init(&argc, &argv, NULL);

    qtest_add_data_func("/numa/mon/default", args, test_mon_default);
    qtest_add_data_func("/numa/mon/cpus/explicit", args, test_mon_explicit);
    qtest_add_data_func("/numa/mon/cpus/partial", args, test_mon_partial);
    qtest_add_data_func("/numa/qmp/cpus/query-cpus", args, test_query_cpus);

    return g_test_run();
}
