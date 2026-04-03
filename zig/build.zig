const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library module
    const bolt12_mod = b.addModule("bolt12", .{
        .root_source_file = b.path("src/bolt12.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests
    const test_step = b.step("test", "Run bolt12 unit tests");

    const test_files = [_][]const u8{
        "src/bigsize.zig",
        "src/bech32.zig",
        "src/tlv.zig",
        "src/merkle.zig",
        "src/offer.zig",
        "src/bolt12.zig",
    };

    for (test_files) |file| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(file),
            .target = target,
            .optimize = optimize,
        });
        const t = b.addTest(.{
            .root_module = test_mod,
        });
        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    // Integration test that uses test vectors
    const integration_mod = b.createModule(.{
        .root_source_file = b.path("src/test_vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    const integration_test = b.addTest(.{
        .root_module = integration_mod,
    });
    const run_integration = b.addRunArtifact(integration_test);
    test_step.dependOn(&run_integration.step);

    // Example executable
    const example_mod = b.createModule(.{
        .root_source_file = b.path("src/example.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_mod.addImport("bolt12", bolt12_mod);
    const example = b.addExecutable(.{
        .name = "bolt12-decode",
        .root_module = example_mod,
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    if (b.args) |args| {
        run_example.addArgs(args);
    }
    const run_step = b.step("run", "Run the example decoder");
    run_step.dependOn(&run_example.step);
}
