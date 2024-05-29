package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentShort = "You like jazz?"
const contentLong = "According to all known laws of aviation there is no way a bee should be able to fly Its wings are too small to get its fat little body off the ground The bee of course flies anyway because bees don't care what humans think is impossible BARRY BENSON Barry is picking out a shirt Yellow black Yellow black Yellow black Yellow black Ooh black and yellow Let's shake it up a little JANET BENSON Barry Breakfast is ready BARRY Coming Hang on a second Barry uses his antenna like a phone Hello ADAM FLAYMAN Through phone Barry Adam BARRY Adam ADAM Can you believe this is happening BARRY I can't I'll pick you up Barry flies down the stairs MARTIN BENSON Looking sharp."

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Custom Test InitUser", func() {

		Specify("Custom Test: Testing InitUser with a username that already exisits", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling InitUser using 'alice' as the username again.")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Initializing an empty username", func() {
			userlib.DebugMsg("Initializing user ''.")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Initializing two different users with different username, same password", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})
	})

	Describe("Custom Tests GetUser", func() {

		Specify("Custom Test: Testing GetUser with a username that doesn't exisit", func() {
			userlib.DebugMsg("Calling GetUser on Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing GetUser with using the wrong password", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling GetUser on Alice using the 'wrongpassword'.")
			aliceLaptop, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (GetUser) DataStore adversary modifies Alice's user struct.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with Datastore: Wiping out the User Struct with random bytes")
			myMap := userlib.DatastoreGetMap()
			for loc, data := range myMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}
			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests LoadFile/StoreFile", func() {

		Specify("Custom Test: Testing StoreFile on emptyString.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: emptyString")
			err = alice.StoreFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Testing StoreFile on a filename that doesn't exist.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Custom Test: Testing StoreFile on a filename that already exists (assuming LoadFile works).", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Custom Test: Testing LoadFile on a filename that doesn't exist in the user's namespace", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to load %s, which does not exist in alice's namespace", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing LoadFile on a shared file, loading using owner's filename, not the shared user's filename", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling InitUser on Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading data using Bob's filename of choice.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading data using Alice's filename. Expect error.")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing LoadFile with a user whose access has been revoked (direct share)", func() {
			userlib.DebugMsg("Initialize User Alice and Bob")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading data using Bob's filename of choice.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob tries LoadFile using his own filename")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries LoadFile using Alice's filename")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing LoadFile with a user whose access has been revoked (indirect share)", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries LoadFile using Alice's filename")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles tries LoadFile using Alice's filename")
			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (StoreFile) DataStore adversary modifies Alice's file, so writing should error.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (LoadFile) DataStore adversary modifies Alice's file, so loading should error.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Custom Tests AppendToFile", func() {
		Specify("Custom Test: Testing AppendToFile with emptyString", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", emptyString)
			err = alice.AppendToFile(aliceFile, []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + emptyString)))
		})

		Specify("Custom Test: Testing AppendToFile on a file that's not in the user's namespace", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to append file data: %s", contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (AppendToFile) DataStore adversary modifies Alice's file.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			// https://edstem.org/us/courses/53368/discussion/4344778?comment=10687196
			// "After an adversary performs malicious action, your function must either
			// return an error, or execute correctly as if the adversary had not performed
			// malicious action."
			// TODO: Decide whether we want err to be nil or not
			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (AppendToFile) Efficiency Test", func() {
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: (emptyString) %s", emptyString)
			bwEmpty := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(emptyString))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bwEmpty)
			Expect(bwEmpty).To(Equal(bwEmpty))

			userlib.DebugMsg("Appending file data: %s", contentShort)
			bwShort := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bwShort)
			Expect(bwShort).To(Equal(bwShort))

			userlib.DebugMsg("Appending file data: %s", contentLong)
			bwLong := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentLong))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bwLong)
			correct := false
			if bwEmpty < bwShort && bwShort < bwLong {
				correct = true
			}
			Expect(correct).To(Equal(true))
		})

		Specify("Custom Test: (AppendToFile) Efficiency Test for Equal Appends", func() {
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentShort)
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw1)

			userlib.DebugMsg("Appending file data: %s", contentShort)
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw2)

			userlib.DebugMsg("Appending file data: %s", contentShort)
			bw3 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw3)
			correct := false
			if bw1 == bw2 && bw2 == bw3 {
				correct = true
			}
			Expect(correct).To(Equal(true))

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending file data: %s", contentShort)
			bw4 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw4)

			userlib.DebugMsg("Bob appending file data: %s", contentShort)
			bw5 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw5)

			userlib.DebugMsg("Bob appending file data: %s", contentShort)
			bw6 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw6)

			charles, err := client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Bob.")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charlie accepting invite from Bob under filename %s.", bobFile)
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles appending file data: %s", contentShort)
			bw7 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw7)

			userlib.DebugMsg("Charles appending file data: %s", contentShort)
			bw8 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw8)

			userlib.DebugMsg("Charles appending file data: %s", contentShort)
			bw9 := measureBandwidth(func() {
				bob.AppendToFile(bobFile, []byte(contentShort))
			})
			userlib.DebugMsg("HERE IS THE BANDWIDTH: %d", bw9)
		})

	})

	Describe("Custom Tests CreateInvitation", func() {
		Specify("Custom Test: Testing CreateInviation for a file that doesn't exist", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s and %s doesn't exist", aliceFile, aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing CreateInviation on a user that doesn't exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s and user Bob doesn't exist", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (CreateInvitation) DataStore adversary modifies Alice's file, so sharing should error.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling InitUser on Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			// https://edstem.org/us/courses/53368/discussion/4344784?comment=10641429
			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Custom Tests AcceptInvitation", func() {
		Specify("Custom Test: Testing AcceptInvitation when Bob already has a file with the chosen filename in his personal file namespace.", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file data: %s", contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to accept invitation using filename already in shared user's filespace.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing AcceptInvitation a revoked user.", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting Invitation")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invitation after being revoked")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (AcceptInvitation) DataStore adversary modifies all of DataStore, so AcceptInvitation should error when Bob calls it.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling InitUser on Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			// AcceptInvitation should return an error if something about the invitationPtr
			// is wrong (e.g. the value at that UUID on Datastore is corrupt or missing,
			// or the user cannot verify that invitationPtr was provided by senderUsername).
			userlib.DebugMsg("Bob trying to accept Alice's invitation with name %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Custom Tests RevokeAccess", func() {
		Specify("Custom Test: Testing when the given filename isn't in the owner's namespace", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice trying to call RevokeAccess on a file that doesn't exist in her namespace.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing RevokeAccess on a file that hasn't been shared with recipient user.", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice trying to revoke access from Bob even though he doesn't have access to begin with:")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing LoadFile/AppendtoFile/CreateInvitation no longer works on directly/indirectly revoked users", func() {
			userlib.DebugMsg("Initializing user Alice, Bob, Charles, and Doris.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris storing file %s with content: %s", dorisFile, contentOne)
			doris.StoreFile(dorisFile, []byte(contentOne))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loading data using %s.", bobFile)
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles appending to file %s, content: %s", charlesFile, contentThree)
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes access from Bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			// Boom access revoked.

			userlib.DebugMsg("Revoked Bob trying to load data using %s.", bobFile)
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked Bob trying to append to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Indirectly Revoked Charlie trying to load data using %s.", charlesFile)
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Indirectly Revoked Charlie trying to append to file %s, content: %s", charlesFile, contentThree)
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked Bob trying to create invite for indirectly Revoked Charles for file %s.", bobFile)
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked Bob trying to create invite for Doris for file %s.", bobFile)
			_, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: (RevokeAccess) DataStore adversary modifies all of DataStore, so RevokeAccess should error when Alice calls it.", func() {
			userlib.DebugMsg("Calling InitUser on Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Calling InitUser on Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file : %s", aliceFile)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation with name %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			dataStoreMap := userlib.DatastoreGetMap()
			userlib.DebugMsg("Tampering with Datastore: Wiping out DataStore with random bytes")
			for loc, data := range dataStoreMap {
				newData := userlib.RandomBytes(len(data))
				userlib.DatastoreSet(loc, newData)
			}

			// RevokeAccess should return an error if revocation cannot be
			// completed due to malicious action.
			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

	})

})
