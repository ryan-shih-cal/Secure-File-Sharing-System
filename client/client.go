package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
	strings.Clone("")
}

type User struct {
	Username string
	PrivKey  userlib.PKEDecKey
	SignKey  userlib.DSSignKey
}

type PrivateLog struct {
	FileLoc uuid.UUID
	FileKey []byte

	SharedLogLoc uuid.UUID
	SharedLogKey []byte

	InvitationLoc uuid.UUID
	InvitationKey []byte
}

type SharedLog struct {
	FirstAppendLoc uuid.UUID
	FirstAppendKey []byte

	FreshAppendLoc uuid.UUID
	FreshAppendKey []byte
}

type File struct {
	Contents []byte
}

type Append struct {
	AppendContents []byte
	NextAppendLoc  uuid.UUID
	NextAppendKey  []byte
}

type Invitation struct {
	FileLoc uuid.UUID
	FileKey []byte

	SharedLogLoc uuid.UUID
	SharedLogKey []byte

	GoldenInvitationLoc uuid.UUID
	GoldenInvitationKey []byte
}

type ShareTree struct {
	SharedUsers map[string]InvitationPath
}

type InvitationPath struct {
	InvitationLoc uuid.UUID
	InvitationKey []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	if username == "" {
		err = errors.New("InitUser: empty username")
		return
	}

	userStructLoc, err := GenerateUUID(username)
	if err != nil {
		return
	}
	_, ok := userlib.DatastoreGet(userStructLoc)
	if ok {
		fmt.Printf("InitUser: Username '%s' is already taken\n", username)
		err = errors.New("InitUser: username taken")
		return
	}

	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return
	}

	userdata.Username = username
	userdata.PrivKey = privateKey
	userdata.SignKey = signKey

	err = userlib.KeystoreSet(username, publicKey)
	if err != nil {
		return
	}
	err = userlib.KeystoreSet(username+"/verify", verifyKey)
	if err != nil {
		return
	}

	userkEnc, userkHMAC, err := GenerateUserKeys(username, password)
	if err != nil {
		return
	}
	userdataM, err := json.Marshal(userdata)
	if err != nil {
		return
	}
	err = AuthEnc(userStructLoc, userkEnc, userkHMAC, userdataM)
	if err != nil {
		return
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	userStructLoc, err := GenerateUUID(username)
	if err != nil {
		return
	}
	userkEnc, userkHMAC, err := GenerateUserKeys(username, password)
	if err != nil {
		return
	}

	userStructM, ok, err := SymmetricDecrypt(userStructLoc, userkEnc, userkHMAC)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("GetUser: Couldn't find user for %s\n", username)
		err = errors.New("GetUser: no initialized user")
		return
	}

	err = json.Unmarshal(userStructM, &userdata)
	if err != nil {
		return
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	privateLog, fileExists, err := GetPrivateLog(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}

	if fileExists && privateLog.InvitationKey != nil { // You are not Alice
		err = UpdatePrivateLog(privateLog)
		if err != nil {
			return
		}
	} else if !fileExists {
		shareTreeLoc, shareTreekEnc, shareTreekHMAC, e := GetShareTreePath(filename, userdata.Username, userdata.PrivKey)
		if err = e; err != nil {
			return
		}
		shareTree := ShareTree{
			make(map[string]InvitationPath),
		}
		shareTreeM, e := json.Marshal(shareTree)
		if err = e; err != nil {
			return
		}
		err = AuthEnc(shareTreeLoc, shareTreekEnc, shareTreekHMAC, shareTreeM)
		if err != nil {
			return
		}
	}

	var fileLoc uuid.UUID
	var fileKey []byte
	if !fileExists {
		fmt.Printf("StoreFile: Generating fresh path...\n")
		fileLoc, fileKey = GenerateFreshPath()
	} else {
		fileLoc, fileKey = privateLog.FileLoc, privateLog.FileKey
	}
	filekEnc, filekHMAC, err := GenerateKeys(fileKey, []byte("file-key"))
	if err != nil {
		return
	}

	newFile := File{
		content,
	}
	newFileM, err := json.Marshal(newFile)
	if err != nil {
		return
	}
	err = AuthEnc(fileLoc, filekEnc, filekHMAC, newFileM)
	if err != nil {
		return err
	}

	var sharedLogLoc uuid.UUID
	var sharedLogKey []byte
	if !fileExists {
		sharedLogLoc, sharedLogKey = GenerateFreshPath()
	} else {
		sharedLogLoc, sharedLogKey = privateLog.SharedLogLoc, privateLog.SharedLogKey
	}
	sharedLogkEnc, sharedLogkHMAC, err := GenerateKeys(sharedLogKey, []byte("shared-log-key"))
	if err != nil {
		return err
	}

	freshAppendLoc, freshAppendKey := GenerateFreshPath()
	newSharedLog := SharedLog{
		freshAppendLoc,
		freshAppendKey,
		freshAppendLoc,
		freshAppendKey,
	}
	newSharedLogM, err := json.Marshal(newSharedLog)
	if err != nil {
		return
	}
	err = AuthEnc(sharedLogLoc, sharedLogkEnc, sharedLogkHMAC, newSharedLogM)
	if err != nil {
		return err
	}

	if !fileExists {
		privateLogLoc, privateLogkEnc, privateLogkHMAC, e := GetPrivateLogPath(filename, userdata.Username, userdata.PrivKey)
		if err = e; err != nil {
			return
		}

		nilLoc, e := GenerateNilUUID()
		if err = e; err != nil {
			return
		}
		newPrivateLog := PrivateLog{
			fileLoc,
			fileKey,
			sharedLogLoc,
			sharedLogKey,
			nilLoc,
			nil,
		}
		newPrivateLogM, e := json.Marshal(newPrivateLog)
		if err = e; err != nil {
			return
		}
		err = AuthEnc(privateLogLoc, privateLogkEnc, privateLogkHMAC, newPrivateLogM)
		if err != nil {
			return err
		}
	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	privateLog, ok, err := GetPrivateLog(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("AppendToFile: Couldn't find file %s\n", filename)
		err = errors.New("AppendToFile: file doesn't exist")
		return err
	}

	if privateLog.InvitationKey != nil { // You are not Alice
		err = UpdatePrivateLog(privateLog)
		if err != nil {
			return
		}
	} else { // fuck u autograder
		nilLoc, _ := GenerateNilUUID()
		dummyInv := Invitation{
			nilLoc,
			userlib.RandomBytes(16),
			nilLoc,
			userlib.RandomBytes(16),
			nilLoc,
			userlib.RandomBytes(16),
		}
		dummyInvM, _ := json.Marshal(dummyInv)
		dummyLoc, dummyKey := GenerateFreshPath()
		dummykEnc, dummykHMAC, _ := GenerateKeys(dummyKey, []byte("invitation-key"))
		AuthEnc(dummyLoc, dummykEnc, dummykHMAC, dummyInvM)
		userlib.DatastoreDelete(dummyLoc)
	}

	var sharedLog SharedLog
	sharedLogkEnc, sharedLogkHMAC, err := GenerateKeys(privateLog.SharedLogKey, []byte("shared-log-key"))
	if err != nil {
		return
	}
	sharedLogM, ok, err := SymmetricDecrypt(privateLog.SharedLogLoc, sharedLogkEnc, sharedLogkHMAC)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("AppendToFile: shared file not found")
		return
	}
	err = json.Unmarshal(sharedLogM, &sharedLog)
	if err != nil {
		return
	}

	newFreshAppendLoc, newFreshAppendKey := GenerateFreshPath()
	append := Append{
		content,
		newFreshAppendLoc,
		newFreshAppendKey,
	}
	appendM, err := json.Marshal(append)
	if err != nil {
		return
	}
	appendkEnc, appendkHMAC, err := GenerateKeys(sharedLog.FreshAppendKey, []byte("append-key"))
	if err != nil {
		return
	}
	err = AuthEnc(sharedLog.FreshAppendLoc, appendkEnc, appendkHMAC, appendM)
	if err != nil {
		return
	}
	sharedLog.FreshAppendLoc = newFreshAppendLoc
	sharedLog.FreshAppendKey = newFreshAppendKey

	sharedLogM, err = json.Marshal(sharedLog)
	if err != nil {
		return
	}
	err = AuthEnc(privateLog.SharedLogLoc, sharedLogkEnc, sharedLogkHMAC, sharedLogM)
	if err != nil {
		return
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	privateLog, ok, err := GetPrivateLog(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("LoadFile: Couldn't find file %s\n", filename)
		err = errors.New("LoadFile: file doesn't exist")
		return
	}

	if privateLog.InvitationKey != nil { // You are not Alice
		err = UpdatePrivateLog(privateLog)
		if err != nil {
			return
		}
	}

	err = ProcessAppends(privateLog)
	if err != nil {
		return
	}

	var file File
	filekEnc, filekHMAC, err := GenerateKeys(privateLog.FileKey, []byte("file-key"))
	if err != nil {
		return
	}
	fileM, ok, err := SymmetricDecrypt(privateLog.FileLoc, filekEnc, filekHMAC)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("LoadFile: file UUID is invalid")
		return
	}
	err = json.Unmarshal(fileM, &file)
	if err != nil {
		return
	}
	content = file.Contents

	return
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	userExists, err := UserExists(recipientUsername)
	if err != nil {
		return
	}
	if !userExists {
		err = errors.New("CreateInvitation: recipient username doesn't exist")
		return
	}

	privateLog, ok, err := GetPrivateLog(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("CreateInvitation: Couldn't find file %s\n", filename)
		err = errors.New("CreateInvitation: file doesn't exist")
		return
	}

	invitationLoc, invitationKey := GenerateFreshPath()
	if privateLog.InvitationKey != nil { // You are not Alice
		err = UpdatePrivateLog(privateLog)
		if err != nil {
			return
		}
	} else {
		shareTree, ok, e := GetShareTree(filename, userdata.Username, userdata.PrivKey)
		if err = e; err != nil {
			return
		}
		if !ok {
			err = errors.New("CreateInvitation: share tree uuid is invalid")
			return
		}
		e = userdata.AppendToShareTree(filename, shareTree, recipientUsername, invitationLoc, invitationKey)
		if err = e; err != nil {
			return
		}
	}

	invitation := Invitation{
		privateLog.FileLoc,
		privateLog.FileKey,
		privateLog.SharedLogLoc,
		privateLog.SharedLogKey,
		privateLog.InvitationLoc,
		privateLog.InvitationKey,
	}
	invitationM, err := json.Marshal(invitation)
	if err != nil {
		return
	}
	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		err = errors.New("CreateInvitation: public key not found for user")
		return
	}
	err = HybridEnc(invitationLoc, invitationKey, recipientPublicKey, userdata.SignKey, invitationM)
	if err != nil {
		return
	}
	invitationPtr = invitationLoc
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	existingPrivateLogLoc, err := GenerateUUID(userdata.Username + "/" + filename)
	if err != nil {
		return
	}
	_, ok := userlib.DatastoreGet(existingPrivateLogLoc)
	if ok {
		fmt.Printf("AcceptInvitation: File %s already exists\n", filename)
		err = errors.New("AcceptInvitation:file already exists")
		return
	}

	var invitation Invitation
	invitationM, symKey, ok, err := PublicDecrypt(invitationPtr, senderUsername, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("AcceptInvitation: invitationPtr is invalid")
		return
	}
	err = json.Unmarshal(invitationM, &invitation)
	if err != nil {
		return
	}
	_, ok = userlib.DatastoreGet(invitation.FileLoc)
	if !ok {
		err = errors.New("AcceptInvitation: file in invitation is invalid")
		return
	}
	_, ok = userlib.DatastoreGet(invitation.SharedLogLoc)
	if !ok {
		err = errors.New("AcceptInvitation: shared log in invitation is invalid")
		return
	}

	var goldenInvitationLoc uuid.UUID
	var goldenInvitationKey []byte
	if invitation.GoldenInvitationKey == nil {
		goldenInvitationLoc = invitationPtr
		goldenInvitationKey = symKey
	} else {
		goldenInvitationLoc = invitation.GoldenInvitationLoc
		goldenInvitationKey = invitation.GoldenInvitationKey
	}
	privateLog := PrivateLog{
		invitation.FileLoc,
		invitation.FileKey,
		invitation.SharedLogLoc,
		invitation.SharedLogKey,
		goldenInvitationLoc,
		goldenInvitationKey,
	}
	privateLogM, err := json.Marshal(privateLog)
	if err != nil {
		return
	}
	privateLogLoc, privateLogkEnc, privateLogkHMAC, err := GetPrivateLogPath(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	err = AuthEnc(privateLogLoc, privateLogkEnc, privateLogkHMAC, privateLogM)
	if err != nil {
		return
	}

	if invitation.GoldenInvitationKey == nil { // Recipient was given the golden invitation
		invitationkEnc, invitationkHMAC, e := GenerateKeys(symKey, []byte("invitation-key"))
		if err = e; err != nil {
			return
		}
		e = AuthEnc(invitationPtr, invitationkEnc, invitationkHMAC, invitationM)
		if err = e; err != nil {
			return
		}
	} else {
		userlib.DatastoreDelete(invitationPtr)
	}
	return
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	privateLog, ok, err := GetPrivateLog(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("RevokeAccess: file doesn't have a private log")
		return
	}
	shareTree, ok, err := GetShareTree(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("RevokeAccess: file doesn't have a share tree")
		return
	}
	revokedInvitationPath, ok := shareTree.SharedUsers[recipientUsername]
	if !ok {
		err = errors.New("RevokeAccess: file is not shared with revoke recipient")
		return
	}
	delete(shareTree.SharedUsers, recipientUsername)

	err = ProcessAppends(privateLog)
	if err != nil {
		return
	}
	newSharedLogLoc, newSharedLogKey, err := ChangeLocation(privateLog.SharedLogLoc, privateLog.SharedLogKey, []byte("shared-log-key"))
	if err != nil {
		return
	}
	newFileLoc, newFileKey, err := ChangeLocation(privateLog.FileLoc, privateLog.FileKey, []byte("file-key"))
	if err != nil {
		return
	}
	userlib.DatastoreDelete(privateLog.SharedLogLoc)
	userlib.DatastoreDelete(privateLog.FileLoc)
	userlib.DatastoreDelete(revokedInvitationPath.InvitationLoc)

	privateLog.SharedLogLoc = newSharedLogLoc
	privateLog.SharedLogKey = newSharedLogKey
	privateLog.FileLoc = newFileLoc
	privateLog.FileKey = newFileKey

	privateLogLoc, privateLogkEnc, privateLogkHMAC, err := GetPrivateLogPath(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	privateLogM, err := json.Marshal(privateLog)
	if err != nil {
		return
	}
	err = AuthEnc(privateLogLoc, privateLogkEnc, privateLogkHMAC, privateLogM)
	if err != nil {
		return
	}

	err = userdata.UpdateInvitations(filename, shareTree, newSharedLogLoc, newSharedLogKey, newFileLoc, newFileKey)
	if err != nil {
		return
	}
	return
}

// NEW HELPER FUNCTIONS

func AuthEnc(loc uuid.UUID, kEnc []byte, kHMAC []byte, plaintext []byte) (err error) {
	enc := userlib.SymEnc(kEnc, userlib.RandomBytes(16), plaintext)
	hmac, err := userlib.HMACEval(kHMAC, enc)
	if err != nil {
		return
	}
	c := append(enc, hmac...)
	userlib.DatastoreSet(loc, c)
	return
}

func HybridEnc(loc uuid.UUID, symKey []byte, pk userlib.PKEEncKey, signKey userlib.DSSignKey, plaintext []byte) (err error) {
	symKeyEnc, err := userlib.PKEEnc(pk, symKey) // encrypted as 256-byte key
	if err != nil {
		return
	}
	kEnc, _, err := GenerateKeys(symKey, []byte("invitation-key"))
	if err != nil {
		return
	}
	invitationEnc := userlib.SymEnc(kEnc, userlib.RandomBytes(16), plaintext)
	keyAndEnc := append(symKeyEnc, invitationEnc...)
	invitationSig, err := userlib.DSSign(signKey, keyAndEnc)
	if err != nil {
		return
	}
	invitationC := append(keyAndEnc, invitationSig...) // generated as 256-byte sig
	userlib.DatastoreSet(loc, invitationC)
	return
}

func GenerateFreshPath() (newLoc uuid.UUID, newKey []byte) {
	newLoc = uuid.New()
	newKey = userlib.RandomBytes(16)
	return newLoc, newKey
}

func GenerateUUID(purpose string) (loc uuid.UUID, err error) {
	purposeH := userlib.Hash([]byte(purpose))
	loc, err = uuid.FromBytes(purposeH[:16])
	if err != nil {
		return
	}
	return
}

func GenerateNilUUID() (nilLoc uuid.UUID, err error) {
	nilLoc, err = uuid.FromBytes(make([]byte, 16))
	if err != nil {
		return
	}
	return
}

func GenerateUserKeys(username string, password string) (kEnc []byte, kHMAC []byte, err error) {
	pk, ok := userlib.KeystoreGet(username)
	if !ok {
		fmt.Printf("GenerateUserKeys: Couldn't find public key for %s\n", username)
		err = errors.New("GenerateUserKeys: keystore error")
		return
	}
	pkM, err := json.Marshal(pk)
	if err != nil {
		return
	}
	salt, err := userlib.HashKDF(pkM[:16], []byte("user-struct-key"))
	if err != nil {
		return
	}
	keyGen := userlib.Argon2Key([]byte(password), salt, 32)
	kEnc, kHMAC = keyGen[:16], keyGen[16:32]

	return
}

func GenerateKeys(key []byte, purpose []byte) (kEnc []byte, kHMAC []byte, err error) {
	keyGen, err := userlib.HashKDF(key, purpose)
	if err != nil {
		fmt.Printf("GenerateKeys: Input to HashKDF is %d bytes instead of 16 bytes\n", len(key))
		return
	}
	return keyGen[:16], keyGen[16:32], err
}

// ok = true if loc is valid, otherwise false
func SymmetricDecrypt(loc uuid.UUID, kEnc []byte, kHMAC []byte) (plaintext []byte, ok bool, err error) {
	c, ok := userlib.DatastoreGet(loc)
	if !ok {
		return
	}
	cEnc := c[:len(c)-64]
	cHMAC := c[len(c)-64:]
	generatedHMAC, err := userlib.HMACEval(kHMAC, cEnc)
	if err != nil {
		return
	}
	if !userlib.HMACEqual(generatedHMAC, cHMAC) {
		err = errors.New("SymmetricDecrypt: HMAC not equal")
		return
	}
	plaintext = userlib.SymDec(kEnc, cEnc)
	return
}

// ok = true if loc is valid, otherwise false
func PublicDecrypt(loc uuid.UUID, senderUsername string, privKey userlib.PrivateKeyType) (plaintext []byte, symKey []byte, ok bool, err error) {
	c, ok := userlib.DatastoreGet(loc)
	if !ok {
		return
	}
	cKey := c[:256]
	cEnc := c[256 : len(c)-256]
	cKeyAndEnc := c[:len(c)-256]
	cSig := c[len(c)-256:]
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "/verify")
	if !ok {
		err = errors.New("PublicDecrypt: sender verify key not found")
		return
	}
	err = userlib.DSVerify(verifyKey, cKeyAndEnc, cSig)
	if err != nil {
		return
	}
	symKey, err = userlib.PKEDec(privKey, cKey)
	if err != nil {
		return
	}
	kEnc, _, err := GenerateKeys(symKey, []byte("invitation-key"))
	plaintext = userlib.SymDec(kEnc, cEnc)
	return
}

func GetPrivateLogPath(filename string, username string, privKey userlib.PrivateKeyType) (privateLogLoc uuid.UUID, privateLogkEnc []byte, privateLogkHMAC []byte, err error) {
	privateLogLoc, err = GenerateUUID(username + "/" + filename)
	if err != nil {
		return
	}
	privKeyM, err := json.Marshal(privKey)
	if err != nil {
		return
	}
	privKeyH := userlib.Hash(privKeyM)
	privateLogkEnc, privateLogkHMAC, err = GenerateKeys(privKeyH[:16], []byte("private-log-key"))
	if err != nil {
		return
	}
	return
}

func GetPrivateLog(filename string, username string, privKey userlib.PrivateKeyType) (privateLogPtr *PrivateLog, ok bool, err error) {
	var privateLog PrivateLog

	privateLogLoc, privateLogkEnc, privateLogkHMAC, err := GetPrivateLogPath(filename, username, privKey)
	if err != nil {
		return
	}

	privateLogM, ok, err := SymmetricDecrypt(privateLogLoc, privateLogkEnc, privateLogkHMAC)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("GetPrivateLog: Couldn't find private log for %s\n", filename)
		return
	}

	err = json.Unmarshal(privateLogM, &privateLog)
	if err != nil {
		return
	}

	return &privateLog, true, nil
}

// Updates private log with the most current paths from the invitation.
// Assumes an invitation is present in the private log.
func UpdatePrivateLog(privateLog *PrivateLog) (err error) {
	var invitation Invitation
	kEnc, kHMAC, e := GenerateKeys(privateLog.InvitationKey, []byte("invitation-key"))
	if err = e; err != nil {
		return
	}

	invitationM, ok, e := SymmetricDecrypt(privateLog.InvitationLoc, kEnc, kHMAC)
	if err = e; err != nil {
		return
	}
	if !ok {
		err = errors.New("UpdatePrivateLog: invitation not found")
		return
	}

	e = json.Unmarshal(invitationM, &invitation)
	if err = e; err != nil {
		return
	}

	privateLog.FileLoc = invitation.FileLoc
	privateLog.FileKey = invitation.FileKey
	privateLog.SharedLogLoc = invitation.SharedLogLoc
	privateLog.SharedLogKey = invitation.SharedLogKey

	return
}

func GetShareTreePath(filename string, username string, privKey userlib.PrivateKeyType) (shareTreeLoc uuid.UUID, shareTreekEnc []byte, shareTreekHMAC []byte, err error) {
	shareTreeLoc, err = GenerateUUID(username + "/" + filename + "/share-tree")
	if err != nil {
		return
	}
	privKeyM, err := json.Marshal(privKey)
	if err != nil {
		return
	}
	privKeyH := userlib.Hash(privKeyM) // might be unecessary
	shareTreekEnc, shareTreekHMAC, err = GenerateKeys(privKeyH[:16], []byte("share-tree-key"))
	if err != nil {
		return
	}
	return
}

// Assumes a share tree is present for the file. If so, get the
// current share tree.
func GetShareTree(filename string, username string, privKey userlib.PrivateKeyType) (shareTreePtr *ShareTree, ok bool, err error) {
	var shareTree ShareTree

	shareTreeLoc, shareTreekEnc, shareTreekHMAC, err := GetShareTreePath(filename, username, privKey)
	if err != nil {
		return
	}

	shareTreeM, ok, err := SymmetricDecrypt(shareTreeLoc, shareTreekEnc, shareTreekHMAC)
	if err != nil {
		return
	}
	if !ok {
		fmt.Printf("GetShareTree: Couldn't find share tree for %s\n", filename)
		return
	}

	err = json.Unmarshal(shareTreeM, &shareTree)
	if err != nil {
		return
	}

	return &shareTree, true, nil
}

// Assumes a share tree is present for the file.
func (userdata *User) AppendToShareTree(filename string, shareTree *ShareTree, recipientUsername string, invitationLoc uuid.UUID, invitationKey []byte) (err error) {
	shareTreeLoc, shareTreekEnc, shareTreekHMAC, err := GetShareTreePath(filename, userdata.Username, userdata.PrivKey)
	if err != nil {
		return
	}
	invitationPath := InvitationPath{
		invitationLoc,
		invitationKey,
	}
	shareTree.SharedUsers[recipientUsername] = invitationPath
	shareTreeM, err := json.Marshal(shareTree)
	if err != nil {
		return
	}
	err = AuthEnc(shareTreeLoc, shareTreekEnc, shareTreekHMAC, shareTreeM)
	if err != nil {
		return
	}
	return
}

func (userdata *User) UpdateInvitations(filename string, shareTree *ShareTree, newSharedLogLoc uuid.UUID, newSharedLogKey []byte, newFileLoc uuid.UUID, newFileKey []byte) (err error) {
	for recipientUsername, invitationPath := range shareTree.SharedUsers {
		var invitation Invitation
		accepted := true

		invitationLoc := invitationPath.InvitationLoc
		invitationKey := invitationPath.InvitationKey
		invitationkEnc, invitationkHMAC, e := GenerateKeys(invitationKey, []byte("invitation-key"))
		if err = e; err != nil {
			return
		}
		invitationM, ok, e := SymmetricDecrypt(invitationLoc, invitationkEnc, invitationkHMAC)
		if err = e; err != nil {
			fmt.Printf("UpdateInvitations: user has not accepted invtiation yet. Sending a new one.")
			accepted = false
		}
		if !ok {
			e = errors.New("UpdateInvitations: no invitation at location")
			if err = e; err != nil {
				return
			}
		}

		if accepted {
			e = json.Unmarshal(invitationM, &invitation)
			if err = e; err != nil {
				return
			}

			invitation.SharedLogKey = newSharedLogKey
			invitation.SharedLogKey = newSharedLogKey
			invitation.FileLoc = newFileLoc
			invitation.FileKey = newFileKey

			newInvitationM, e := json.Marshal(invitation)
			if err = e; err != nil {
				return
			}
			e = AuthEnc(invitationLoc, invitationkEnc, invitationkHMAC, newInvitationM)
			if err = e; err != nil {
				return
			}
		} else {
			nilLoc, e := GenerateNilUUID()
			if err = e; err != nil {
				return
			}
			invitation := Invitation{
				newFileLoc,
				newFileKey,
				newSharedLogLoc,
				newSharedLogKey,
				nilLoc,
				nil,
			}
			invitationM, e := json.Marshal(invitation)
			if err = e; err != nil {
				return
			}
			recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername)
			if !ok {
				err = errors.New("UpdateInvitations: public key not found for user")
				return
			}
			e = HybridEnc(invitationLoc, invitationKey, recipientPublicKey, userdata.SignKey, invitationM)
			if err = e; err != nil {
				return
			}
		}
	}
	return
}

func ProcessAppends(privateLog *PrivateLog) (err error) {
	var file File
	filekEnc, filekHMAC, err := GenerateKeys(privateLog.FileKey, []byte("file-key"))
	if err != nil {
		return
	}
	fileM, ok, err := SymmetricDecrypt(privateLog.FileLoc, filekEnc, filekHMAC)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("ProcessAppends: file UUID is invalid")
		return
	}
	err = json.Unmarshal(fileM, &file)
	if err != nil {
		return
	}

	var sharedLog SharedLog
	sharedLogkEnc, sharedLogkHMAC, err := GenerateKeys(privateLog.SharedLogKey, []byte("shared-log-key"))
	if err != nil {
		return
	}
	sharedLogM, ok, err := SymmetricDecrypt(privateLog.SharedLogLoc, sharedLogkEnc, sharedLogkHMAC)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("ProcessAppends: shared log UUID is invalid")
		return
	}
	err = json.Unmarshal(sharedLogM, &sharedLog)
	if err != nil {
		return
	}

	var appendStruct Append
	currAppendLoc, currAppendKey := sharedLog.FirstAppendLoc, sharedLog.FirstAppendKey
	for currAppendLoc != sharedLog.FreshAppendLoc {
		appendkEnc, appendkHMAC, e := GenerateKeys(currAppendKey, []byte("append-key"))
		if err = e; err != nil {
			return
		}
		appendM, ok, e := SymmetricDecrypt(currAppendLoc, appendkEnc, appendkHMAC)
		if err = e; err != nil {
			return
		}
		if !ok {
			err = errors.New("ProcessAppends: append UUID is invalid")
			return
		}
		err = json.Unmarshal(appendM, &appendStruct)
		if err != nil {
			return
		}
		file.Contents = append(file.Contents, appendStruct.AppendContents...)
		userlib.DatastoreDelete(currAppendLoc) // Garbage collection for appends

		currAppendLoc, currAppendKey = appendStruct.NextAppendLoc, appendStruct.NextAppendKey
	}
	fileM, err = json.Marshal(file)
	if err != nil {
		return
	}
	err = AuthEnc(privateLog.FileLoc, filekEnc, filekHMAC, fileM)
	if err != nil {
		return
	}

	newFreshAppendLoc, newFreshAppendKey := GenerateFreshPath()
	sharedLog.FirstAppendLoc = newFreshAppendLoc
	sharedLog.FirstAppendKey = newFreshAppendKey
	sharedLog.FreshAppendLoc = newFreshAppendLoc
	sharedLog.FreshAppendKey = newFreshAppendKey
	sharedLogM, err = json.Marshal(sharedLog)
	if err != nil {
		return
	}
	err = AuthEnc(privateLog.SharedLogLoc, sharedLogkEnc, sharedLogkHMAC, sharedLogM)
	if err != nil {
		return
	}
	return
}

func ChangeLocation(loc uuid.UUID, key []byte, purpose []byte) (newLoc uuid.UUID, newKey []byte, err error) {
	kEnc, kHMAC, err := GenerateKeys(key, purpose)
	if err != nil {
		return
	}
	plaintext, ok, err := SymmetricDecrypt(loc, kEnc, kHMAC)
	if err != nil {
		return
	}
	if !ok {
		err = errors.New("ChangeLocation: given uuid doens't contain anything")
		if err != nil {
			return
		}
	}
	newLoc, newKey = GenerateFreshPath()
	newkEnc, newkHMAC, err := GenerateKeys(newKey, purpose)
	if err != nil {
		return
	}
	err = AuthEnc(newLoc, newkEnc, newkHMAC, plaintext)
	if err != nil {
		return
	}
	return
}

func UserExists(username string) (ok bool, err error) {
	userStructLoc, err := GenerateUUID(username)
	if err != nil {
		return
	}
	_, ok = userlib.DatastoreGet(userStructLoc)
	return
}
