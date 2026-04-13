//go:build windows

package water

import (
    "errors"
    "fmt"
    "io"
    "log/slog"
    "os/exec"
    "runtime"

    "golang.org/x/sys/windows"
    "golang.zx2c4.com/wintun"
)

type Wintun struct {
    adapter   *wintun.Adapter
    session   wintun.Session
    waitEvent windows.Handle
}

func (tun *Wintun) Read(p []byte) (int, error) {
    for {
        packet, err := tun.session.ReceivePacket()
        if err == nil {
            n := copy(p, packet)
            tun.session.ReleaseReceivePacket(packet)
            if n < len(packet) {
                return n, io.ErrShortBuffer
            }
            return n, nil
        }
        if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
            windows.WaitForSingleObject(tun.waitEvent, windows.INFINITE)
            continue
        }
        return 0, err
    }
}

func (tun *Wintun) Write(p []byte) (int, error) {
    for {
        sendPacket, err := tun.session.AllocateSendPacket(len(p))
        if err != nil {
            if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
                slog.Warn("buffer too small")
                runtime.Gosched()
                continue
            }
            return 0, err
        }

        copy(sendPacket, p)
        tun.session.SendPacket(sendPacket)
        return len(p), nil
    }
}

func (tun *Wintun) Close() error {
    defer tun.session.End()
    return tun.adapter.Close()
}

func NewWintun(name, subnet, gateway, dns string, ringBufSize uint32) (io.ReadWriteCloser, error) {
    guid, err := windows.GUIDFromString("{1ba1e400-436f-4abf-b603-ef84c583d610}")
    var adapter *wintun.Adapter
    for i := 0; i < 2; i++ {
        adapter, err = wintun.CreateAdapter(name, "Wintun", &guid)
        if err == nil {
            break
        }
    }
    if err != nil {
        return nil, err
    }

    cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", name, "static", subnet, fmt.Sprintf("gateway=%s", gateway), "gwmetric=1")
    if out, err := cmd.CombinedOutput(); err != nil {
        adapter.Close()
        return nil, fmt.Errorf("%v: %s", err, out)
    }

    cmd = exec.Command("netsh", "interface", "ipv4", "set", "dns", name, "static", dns, "register=none", "validate=no")
    if out, err := cmd.CombinedOutput(); err != nil {
        adapter.Close()
        return nil, fmt.Errorf("%v: %s", err, out)
    }

    session, err := adapter.StartSession(ringBufSize)
    if err != nil {
        adapter.Close()
        return nil, err
    }

    return &Wintun{adapter, session, session.ReadWaitEvent()}, nil
}
