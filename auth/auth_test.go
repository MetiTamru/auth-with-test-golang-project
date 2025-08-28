package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestRegister(t *testing.T) {
	t.Run("a new user should be registered successfully", func(t *testing.T) {

		user := NewAuthService()

		err := user.Register("meti", "meti1234")

		if err != nil {
			t.Errorf("expected no error but got %v", err)
		}
	})

	t.Run("should return error for empty username", func(t *testing.T) {
		user := NewAuthService()

		err := user.Register("", "password123")

		if err == nil {
			t.Fatal("expected error but got none")
		}

		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("expected empty validation error, got %v", err)
		}
	})

	t.Run("should return error for empty password", func(t *testing.T) {
		user := NewAuthService()

		err := user.Register("username", "")

		if err == nil {
			t.Fatal("expected error but got none")
		}

		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("expected empty validation error, got %v", err)
		}
	})

	t.Run("should return error for existing username", func(t *testing.T) {

		user := NewAuthService()

		err := user.Register("meti", "meti1234")
		if err != nil {
			t.Fatalf("first registration failed: %v", err)
		}

		err = user.Register("meti", "qwerty")

		if err == nil {
			t.Fatal("expected error for duplicate username but got none")
		}

		if !strings.Contains(err.Error(), "already exist") {
			t.Errorf("expected duplicate username error, got %v", err)
		}
	})

	t.Run("should handle special characters in username and password", func(t *testing.T) {
		user := NewAuthService()

		username := "meti@gmail.com"
		password := "@meti##**"

		err := user.Register(username, password)
		if err != nil {
			t.Errorf("failed to register user with special characters: %v", err)
		}
	})

	t.Run("this should hash the password", func(t *testing.T) {
		user := NewAuthService().(*authService)

		password := "meti1234"

		err := user.Register("meti", password)

		if err != nil {
			t.Fatalf("registration faild %v", err)
		}

		user.mu.RLock()
		storedHash := user.users["meti"]
		user.mu.RUnlock()

		if storedHash == password {
			t.Error("the password is not hashed it is stored in plain text")
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))

		if err != nil {
			t.Errorf("the stored hash is not valid %v", err)
		}
	})

	t.Run("handling concurrent registration safely", func(t *testing.T) {
		user := NewAuthService()
		var wg sync.WaitGroup
		trail := 100

		results := make(chan error, trail)

		for i := 0; i < trail; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := user.Register("New_user", "newuser12")
				results <- err
			}()
		}

		wg.Wait()
		close(results)

		successCount := 0
		failureCount := 0

		for err := range results {
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}

		if successCount != 1 {
			t.Errorf("expected 1 success, got %d", successCount)
		}
		if failureCount != trail-1 {
			t.Errorf("expected 1 failure, got %d", failureCount)
		}
	})
}

func TestLogin(t *testing.T) {
	t.Run("should login users that are existing", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		token, err := user.Login("meti", "meti1234")

		if err != nil {
			t.Fatalf("expected no error but got %v", err)
		}

		expectedToken := "jwt_token_for_meti"

		if token != expectedToken {
			t.Errorf("expected token %s, but got %s", expectedToken, token)
		}
	})

	t.Run("empty user name field should result error", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		token, err := user.Login("", "meti1234")

		if err == nil {
			t.Fatalf("expected %v error but got none", err)
		}

		if token != "" {
			t.Errorf("expected no token, but got %s", token)
		}

		if !strings.Contains(err.Error(), "username and password cannot be empty") {
			t.Errorf("expected username and password cannot be empty error, got %v", err)
		}
	})

	t.Run("empty password field should result error", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		token, err := user.Login("meti", "")

		if err == nil {
			t.Fatalf("expected %v error but got none", err)
		}

		if token != "" {
			t.Errorf("expected no token, but got %s", token)
		}

		if !strings.Contains(err.Error(), "username and password cannot be empty") {
			t.Errorf("expected username and password cannot be empty error, got %v", err)
		}
	})

	t.Run("should return error for non existing user", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		token, err := user.Login("metiTamir", "meti1234")

		if err == nil {
			t.Fatalf("expected %v error but got none", err)
		}

		if token != "" {
			t.Errorf("expected no token, but got %s", token)
		}

		if !strings.Contains(err.Error(), "this user does not exist") {
			t.Errorf("expected this user does not exist error, got %v", err)
		}
	})

	t.Run("should return error for wrong password", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		token, err := user.Login("meti", "metiTamir")

		if err == nil {
			t.Fatalf("expected %v error but got none", err)
		}

		if token != "" {
			t.Errorf("expected no token, but got %s", token)
		}

		if !strings.Contains(err.Error(), "invalid password") {
			t.Errorf("expected invalid password error, got %v", err)
		}
	})

	t.Run("should handle special characters in username and password", func(t *testing.T) {
		user := NewAuthService()

		user.Register("meti@gmail.com", "@meti##**")

		username := "meti@gmail.com"
		password := "@meti##**"

		token, err := user.Login(username, password)

		if err != nil {
			t.Errorf("failed to find user account with special characters: %v", err)
		}

		expectedToken := "jwt_token_for_meti@gmail.com"

		if token != expectedToken {
			t.Errorf("expected %s but got %s", expectedToken, token)
		}

	})

	t.Run("handling concurrent login safely", func(t *testing.T) {
		user := NewAuthService()
		user.Register("meti", "meti1234")
		var wg sync.WaitGroup
		trail := 100

		results := make(chan error, trail)

		for i := 0; i < trail; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := user.Login("meti", "meti1234")
				results <- err
			}()
		}

		wg.Wait()
		close(results)

for err := range results {
        if err != nil {
            t.Errorf("expected all logins to succeed, got error: %v", err)
        }
    }
	})
}

func BenchmarkRegister(b *testing.B) {
    user := NewAuthService()
    for i := 0; i < b.N; i++ {
        user.Register(fmt.Sprintf("meti %d", i), "meti1234")
    }
}

func BenchmarkLogin(b *testing.B) {
    user := NewAuthService()
    user.Register("meti", "meti1234")
    for i := 0; i < b.N; i++ {
        user.Login("meti", "meti1234")
    }
}