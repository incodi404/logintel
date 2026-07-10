package dbusengine

import (
	"context"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

func SubscribeToSystemdServices(ctx context.Context, logs chan<- *dbus.UnitStatus, extErrCh chan<- error) {
	// opening conn
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		extErrCh <- err
		return
	}
	defer conn.Close()

	// Required before SubscribeUnitsContext
	if err := conn.Subscribe(); err != nil {
		extErrCh <- err
		return
	}

	statusCh, errCh := conn.SubscribeUnitsContext(
		ctx,
		1*time.Second,
	)

	for {
		select {
		case <-ctx.Done():
			return
		case units := <-statusCh: // whenever statusCh get something, we get the data
			for _, status := range units {
				logs <- status // write to chan
			}

		case err := <-errCh:
			extErrCh <- err // write err to chan
		}
	}
}
