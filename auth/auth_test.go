package auth

import (
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
		service := NewAuthService()
		
		username := "meti@gmail.com"
		password := "@meti##**"

		err := service.Register(username, password)
		if err != nil {
			t.Errorf("failed to register user with special characters: %v", err)
		}
	})


	t.Run("this should hash the password",func(t *testing.T) {
		user := NewAuthService().(*authService)

		password := "meti1234"

		err := user.Register("meti",password)

		if err != nil {
			t.Fatalf("registration faild %v",err)
		}

		user.mu.RLock()
		storedHash := user.users["meti"]
		user.mu.RUnlock()

		if storedHash == password{
			t.Error("the password is not hashed it is stored in plain text")
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))

		if err != nil{
			t.Errorf("the stored hash is not valid %v",err)
		}
	})

	t.Run("handling concurrent registration safely",func(t *testing.T) {
		user := NewAuthService()
		var wg sync.WaitGroup
		trail := 100

		results := make(chan error,trail)

		for i := 0; i < trail; i++ {
			wg.Add(1)
			go func ()  {
				defer wg.Done()
				err := user.Register("New_user","newuser12")
				results <- err
			}()
		}

		wg.Wait()
		close(results)

		successCount := 0
		failureCount := 0

		for err := range results{
			if err == nil {
				successCount++
			} else {
				failureCount++
			}
		}

		if successCount != 1 {
			t.Errorf("expected 1 success, got %d",successCount)
		}
		if failureCount != trail-1 {
			t.Errorf("expected 1 failure, got %d",failureCount)
		}
	})
}

