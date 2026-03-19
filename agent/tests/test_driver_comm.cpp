/*
 * test_driver_comm.cpp
 * AkesoDLP Agent - Driver Communication Tests
 *
 * Tests for the user-mode driver communication component.
 * Note: Full integration testing requires the minifilter driver to be
 * loaded. These tests validate construction, state management, callback
 * wiring, and notification parsing without requiring a running driver.
 */

#include "akeso/driver_comm.h"

#include <gtest/gtest.h>

namespace akeso::dlp {
namespace {

/* ================================================================== */
/*  Helper: default config                                             */
/* ================================================================== */

DriverConfig MakeTestConfig()
{
    DriverConfig cfg;
    cfg.port_name = "\\\\AkesoDLPPort";
    cfg.max_connections = 4;
    cfg.message_buffer_size = 65536;
    return cfg;
}

/* ================================================================== */
/*  Construction and defaults                                          */
/* ================================================================== */

TEST(DriverCommTest, Construction_DefaultState)
{
    DriverComm comm(MakeTestConfig());

    EXPECT_EQ(comm.Name(), "DriverComm");
    EXPECT_FALSE(comm.IsConnected());
    EXPECT_FALSE(comm.IsHealthy());
    EXPECT_EQ(comm.NotificationsReceived(), 0u);
    EXPECT_EQ(comm.VerdictsSent(), 0u);
}

TEST(DriverCommTest, DoubleStop_NoThrow)
{
    DriverComm comm(MakeTestConfig());

    /* Stop without Start should be safe */
    EXPECT_NO_THROW(comm.Stop());
    EXPECT_NO_THROW(comm.Stop());
}

/* ================================================================== */
/*  Callback management                                                */
/* ================================================================== */

TEST(DriverCommTest, SetVerdictCallback_Accepted)
{
    DriverComm comm(MakeTestConfig());

    bool called = false;
    comm.SetVerdictCallback([&](const FileNotification&) {
        called = true;
        return DriverMsgType::VerdictAllow;
    });

    /* Callback is stored but not invoked until notifications arrive */
    EXPECT_FALSE(called);
}

TEST(DriverCommTest, SetVerdictCallback_Replace)
{
    DriverComm comm(MakeTestConfig());

    int call_count = 0;
    comm.SetVerdictCallback([&](const FileNotification&) {
        call_count = 1;
        return DriverMsgType::VerdictAllow;
    });

    comm.SetVerdictCallback([&](const FileNotification&) {
        call_count = 2;
        return DriverMsgType::VerdictBlock;
    });

    /* Second callback replaced the first — no side effects without driver */
    EXPECT_EQ(call_count, 0);
}

TEST(DriverCommTest, SetVerdictCallback_Null)
{
    DriverComm comm(MakeTestConfig());

    comm.SetVerdictCallback(nullptr);

    /* Setting null callback should be safe */
    EXPECT_FALSE(comm.IsConnected());
}

/* ================================================================== */
/*  Connection failure (no driver loaded)                              */
/* ================================================================== */

TEST(DriverCommTest, Start_FailsWithoutDriver)
{
    DriverComm comm(MakeTestConfig());

    /* Start should fail gracefully when driver isn't loaded */
    bool started = comm.Start();
    EXPECT_FALSE(started);
    EXPECT_FALSE(comm.IsConnected());
    EXPECT_FALSE(comm.IsHealthy());
}

TEST(DriverCommTest, SendConfigUpdate_FailsWhenDisconnected)
{
    DriverComm comm(MakeTestConfig());

    /* Should fail gracefully when not connected */
    bool result = comm.SendConfigUpdate();
    EXPECT_FALSE(result);
}

/* ================================================================== */
/*  Enum value checks (must match driver header)                       */
/* ================================================================== */

TEST(DriverCommTest, DriverMsgType_ValuesMatchDriver)
{
    /* These must match AKESO_MSG_TYPE in akeso_dlp_filter.h */
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::FileWrite), 1u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::FileCreate), 2u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::VerdictAllow), 3u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::VerdictBlock), 4u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::VerdictScanFull), 5u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::ScanResult), 6u);
    EXPECT_EQ(static_cast<unsigned int>(DriverMsgType::ConfigUpdate), 7u);
}

TEST(DriverCommTest, VolumeType_ValuesMatchDriver)
{
    /* These must match AKESO_VOLUME_TYPE in akeso_dlp_filter.h */
    EXPECT_EQ(static_cast<unsigned int>(VolumeType::Fixed), 0u);
    EXPECT_EQ(static_cast<unsigned int>(VolumeType::Removable), 1u);
    EXPECT_EQ(static_cast<unsigned int>(VolumeType::Network), 2u);
    EXPECT_EQ(static_cast<unsigned int>(VolumeType::Unknown), 3u);
}

/* ================================================================== */
/*  FileNotification struct                                            */
/* ================================================================== */

TEST(DriverCommTest, FileNotification_DefaultConstruction)
{
    FileNotification notif;
    notif.type = DriverMsgType::FileWrite;
    notif.process_id = 1234;
    notif.volume_type = VolumeType::Removable;
    notif.file_size = 8192;
    notif.file_path = L"\\Device\\HarddiskVolume2\\test.docx";
    notif.content_preview = {0x50, 0x4B, 0x03, 0x04};  /* ZIP magic */

    EXPECT_EQ(notif.type, DriverMsgType::FileWrite);
    EXPECT_EQ(notif.process_id, 1234u);
    EXPECT_EQ(notif.volume_type, VolumeType::Removable);
    EXPECT_EQ(notif.file_size, 8192);
    EXPECT_FALSE(notif.file_path.empty());
    EXPECT_EQ(notif.content_preview.size(), 4u);
}

TEST(DriverCommTest, FileNotification_LargePath)
{
    FileNotification notif;
    notif.type = DriverMsgType::FileCreate;
    notif.process_id = 5678;
    notif.volume_type = VolumeType::Network;
    notif.file_size = 0;

    /* Simulate a long UNC path */
    std::wstring long_path = L"\\\\server\\share\\";
    for (int i = 0; i < 50; ++i) {
        long_path += L"subdir\\";
    }
    long_path += L"document.xlsx";
    notif.file_path = long_path;

    EXPECT_GT(notif.file_path.size(), 300u);
}

TEST(DriverCommTest, FileNotification_EmptyPreview)
{
    FileNotification notif;
    notif.type = DriverMsgType::FileCreate;
    notif.process_id = 0;
    notif.volume_type = VolumeType::Fixed;
    notif.file_size = 0;

    /* Empty content preview is valid (e.g., zero-byte file) */
    EXPECT_TRUE(notif.content_preview.empty());
}

/* ================================================================== */
/*  VerdictCallback type                                               */
/* ================================================================== */

TEST(DriverCommTest, VerdictCallback_AllowVerdict)
{
    VerdictCallback cb = [](const FileNotification&) {
        return DriverMsgType::VerdictAllow;
    };

    FileNotification notif;
    notif.type = DriverMsgType::FileWrite;
    notif.process_id = 100;
    notif.volume_type = VolumeType::Fixed;
    notif.file_size = 1024;

    EXPECT_EQ(cb(notif), DriverMsgType::VerdictAllow);
}

TEST(DriverCommTest, VerdictCallback_BlockVerdict)
{
    VerdictCallback cb = [](const FileNotification& n) {
        if (n.volume_type == VolumeType::Removable) {
            return DriverMsgType::VerdictBlock;
        }
        return DriverMsgType::VerdictAllow;
    };

    FileNotification usb_notif;
    usb_notif.type = DriverMsgType::FileWrite;
    usb_notif.process_id = 200;
    usb_notif.volume_type = VolumeType::Removable;
    usb_notif.file_size = 2048;

    FileNotification local_notif;
    local_notif.type = DriverMsgType::FileWrite;
    local_notif.process_id = 300;
    local_notif.volume_type = VolumeType::Fixed;
    local_notif.file_size = 512;

    EXPECT_EQ(cb(usb_notif), DriverMsgType::VerdictBlock);
    EXPECT_EQ(cb(local_notif), DriverMsgType::VerdictAllow);
}

TEST(DriverCommTest, VerdictCallback_ScanFullVerdict)
{
    VerdictCallback cb = [](const FileNotification& n) {
        if (n.file_size > 4096) {
            return DriverMsgType::VerdictScanFull;
        }
        return DriverMsgType::VerdictAllow;
    };

    FileNotification large_file;
    large_file.type = DriverMsgType::FileWrite;
    large_file.process_id = 400;
    large_file.volume_type = VolumeType::Network;
    large_file.file_size = 1048576;  /* 1 MB */

    FileNotification small_file;
    small_file.type = DriverMsgType::FileWrite;
    small_file.process_id = 500;
    small_file.volume_type = VolumeType::Network;
    small_file.file_size = 256;

    EXPECT_EQ(cb(large_file), DriverMsgType::VerdictScanFull);
    EXPECT_EQ(cb(small_file), DriverMsgType::VerdictAllow);
}

/* ================================================================== */
/*  Statistics                                                         */
/* ================================================================== */

TEST(DriverCommTest, Statistics_InitiallyZero)
{
    DriverComm comm(MakeTestConfig());

    EXPECT_EQ(comm.NotificationsReceived(), 0u);
    EXPECT_EQ(comm.VerdictsSent(), 0u);
}

/* ================================================================== */
/*  Component name                                                     */
/* ================================================================== */

TEST(DriverCommTest, Name_ReturnsDriverComm)
{
    DriverComm comm(MakeTestConfig());
    EXPECT_EQ(comm.Name(), "DriverComm");
}

}  // namespace
}  // namespace akeso::dlp
