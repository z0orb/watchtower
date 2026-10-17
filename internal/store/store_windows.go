package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Dir is %ProgramData%\Watchtower.
func Dir() string { return filepath.Join(os.Getenv("ProgramData"), "Watchtower") }

// SYSTEM and Administrators get full control, Users read-only; protected from ProgramData's
// default ACL, which lets any user create files.
const dirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

// Init creates Dir with an admin-only ACL. It refuses an existing Dir not owned by SYSTEM or
// Administrators, since an unprivileged user could have planted it to forge the trusted gateway list.
func Init() error {
	sd, err := windows.SecurityDescriptorFromString(dirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(Dir())
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(p, sa)
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	cur, err := windows.GetNamedSecurityInfo(Dir(), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := cur.Owner()
	if err != nil {
		return err
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("%s is owned by %s, not SYSTEM or Administrators: delete it and start again", Dir(), owner)
}
