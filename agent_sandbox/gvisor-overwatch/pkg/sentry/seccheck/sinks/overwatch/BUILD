load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "overwatch",
    srcs = [
        "overwatch.go",
        "wire.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/wire",
        "//pkg/sync",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "overwatch_test",
    srcs = ["wire_test.go"],
    library = ":overwatch",
)
