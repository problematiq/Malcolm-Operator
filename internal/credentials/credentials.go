// Package credentials generates random secrets and the password hash formats
// Malcolm expects (MD5-crypt for MALCOLM_PASSWORD and bcrypt for htpasswd).
package credentials

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// Random returns a cryptographically random alphanumeric string of length n.
func Random(n int) (string, error) {
	var b strings.Builder
	b.Grow(n)
	max := big.NewInt(int64(len(alphanumeric)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("reading random bytes: %w", err)
		}
		b.WriteByte(alphanumeric[idx.Int64()])
	}
	return b.String(), nil
}

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// MD5Crypt returns the "$1$salt$hash" MD5-crypt digest of password, as produced
// by `openssl passwd -1 -salt <salt> <password>`. A random 8-character salt is
// used when salt is empty.
func MD5Crypt(password, salt string) (string, error) {
	if salt == "" {
		var b strings.Builder
		for i := 0; i < 8; i++ {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(cryptAlphabet))))
			if err != nil {
				return "", fmt.Errorf("reading random bytes: %w", err)
			}
			b.WriteByte(cryptAlphabet[idx.Int64()])
		}
		salt = b.String()
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	const magic = "$1$"
	pw := []byte(password)
	sl := []byte(salt)

	alt := md5.New()
	alt.Write(pw)
	alt.Write(sl)
	alt.Write(pw)
	altSum := alt.Sum(nil)

	ctx := md5.New()
	ctx.Write(pw)
	ctx.Write([]byte(magic))
	ctx.Write(sl)
	for i := len(pw); i > 0; i -= 16 {
		if i > 16 {
			ctx.Write(altSum)
		} else {
			ctx.Write(altSum[:i])
		}
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 != 0 {
			ctx.Write([]byte{0})
		} else {
			ctx.Write(pw[:1])
		}
	}
	final := ctx.Sum(nil)

	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 != 0 {
			c.Write(pw)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(sl)
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 != 0 {
			c.Write(final)
		} else {
			c.Write(pw)
		}
		final = c.Sum(nil)
	}

	var out strings.Builder
	out.WriteString(magic)
	out.Write(sl)
	out.WriteByte('$')
	to64 := func(v uint32, n int) {
		for ; n > 0; n-- {
			out.WriteByte(cryptAlphabet[v&0x3f])
			v >>= 6
		}
	}
	to64(uint32(final[0])<<16|uint32(final[6])<<8|uint32(final[12]), 4)
	to64(uint32(final[1])<<16|uint32(final[7])<<8|uint32(final[13]), 4)
	to64(uint32(final[2])<<16|uint32(final[8])<<8|uint32(final[14]), 4)
	to64(uint32(final[3])<<16|uint32(final[9])<<8|uint32(final[15]), 4)
	to64(uint32(final[4])<<16|uint32(final[10])<<8|uint32(final[5]), 4)
	to64(uint32(final[11]), 2)
	return out.String(), nil
}

// Htpasswd returns an htpasswd line "username:$2y$..." using bcrypt, as
// produced by `htpasswd -bnB <username> <password>`.
func Htpasswd(username, password string) (string, error) {
	if strings.Contains(username, ":") {
		return "", fmt.Errorf("username must not contain ':'")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// $2a$ and $2y$ are the same algorithm; htpasswd and PHP emit $2y$.
	hash := string(h)
	if strings.HasPrefix(hash, "$2a$") {
		hash = "$2y$" + hash[4:]
	}
	return username + ":" + hash, nil
}

// VerifyHtpasswd reports whether an htpasswd line matches username/password.
func VerifyHtpasswd(line, username, password string) bool {
	u, hash, ok := strings.Cut(line, ":")
	if !ok || u != username {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// VerifyMD5Crypt reports whether an MD5-crypt hash matches password.
func VerifyMD5Crypt(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}
	got, err := MD5Crypt(password, parts[2])
	return err == nil && got == hash
}
