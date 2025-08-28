package auth

import (
    "fmt"
    "strings"
    "sync"
    "testing"
    "golang.org/x/crypto/bcrypt"
)

func assertNoError(t *testing.T, err error) {
    t.Helper()
    if err != nil {
        t.Fatalf("expected no error, got %v", err)
    }
}

func assertError(t *testing.T, err error) {
    t.Helper()
    if err == nil {
        t.Fatal("expected error but got none")
    }
}

func assertErrorContains(t *testing.T, err error, expectedContains string) {
    t.Helper()
    assertError(t, err)
    if !strings.Contains(err.Error(), expectedContains) {
        t.Fatalf("expected error containing '%s', got '%v'", expectedContains, err)
    }
}

func assertEqual[T comparable](t *testing.T, got, want T) {
    t.Helper()
    if got != want {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestRegister(t *testing.T) {
    t.Run("successful registration", func(t *testing.T) {
        user := NewAuthService()
        err := user.Register("meti", "meti1234")
        
        assertNoError(t, err)
    })

    t.Run("registration with empty username", func(t *testing.T) {
        user := NewAuthService()
        err := user.Register("", "meti1234")
        
        assertErrorContains(t, err, "cannot be empty")
    })

    t.Run("registration with empty password", func(t *testing.T) {
        user := NewAuthService()
        err := user.Register("meti", "")
        
        assertErrorContains(t, err, "cannot be empty")
    })

    t.Run("duplicate username registration", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        err := user.Register("meti", "meti2244")
        
        assertErrorContains(t, err, "already exist")
    })

    t.Run("registration with special characters", func(t *testing.T) {
        user := NewAuthService()
				err := user.Register("meti@gmail.com", "@meti##**")
        

				assertNoError(t, err)
    })

    t.Run("password should be hashed when registering a user", func(t *testing.T) {
        user := NewAuthService().(*authService)
        password := "meti1234"
        
         err := user.Register("meti", password)
        assertNoError(t, err)
        
         user.mu.RLock()
        storedHash := user.users["meti"]
        user.mu.RUnlock()
        
         assertEqual(t, storedHash == password, false)
        

				err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
        assertNoError(t, err)
    })

    t.Run("concurrent registration safety", func(t *testing.T) {
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
        for err := range results {
            if err == nil {
                successCount++
            }
        }
        assertEqual(t, successCount, 1) 
    })
}

func TestLogin(t *testing.T) {
    t.Run("successful login with valid user", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        
         token, err := user.Login("meti", "meti1234")
        

				assertNoError(t, err)
        assertEqual(t, token, "jwt_token_for_meti")
    })

    t.Run("login with empty username", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        
        token, err := user.Login("", "meti1234")
        
        assertErrorContains(t, err, "cannot be empty")
        assertEqual(t, token, "")
    })

    t.Run("login with empty password", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        
        token, err := user.Login("meti", "")
        
        assertErrorContains(t, err, "cannot be empty")
        assertEqual(t, token, "")
    })

    t.Run("login with non-existent user", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        

				token, err := user.Login("nonexistent", "meti1234")
        
        assertErrorContains(t, err, "does not exist")
        assertEqual(t, token, "")
    })

    t.Run("login with wrong password", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
        
        token, err := user.Login("meti", "wrongpassword")
        

				assertErrorContains(t, err, "invalid password")
        assertEqual(t, token, "")
    })

    t.Run("login with special characters", func(t *testing.T) {
        user := NewAuthService()
        assertNoError(t, user.Register("meti@gmail.com", "@meti##**"))
        

				token, err := user.Login("meti@gmail.com", "@meti##**")
        
        assertNoError(t, err)
        assertEqual(t, token, "jwt_token_for_meti@gmail.com")
    })

    t.Run("safe concurrent login", func(t *testing.T) {

			user := NewAuthService()
        assertNoError(t, user.Register("meti", "meti1234"))
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
            assertNoError(t, err)
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