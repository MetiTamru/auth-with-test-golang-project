package auth

import (
	
	"errors"
	"sync"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Register(username, password string) error
	Login(username, password string) (string, error)
}

type authService struct {
	users map[string]string 
	mu    sync.RWMutex
}

func NewAuthService() AuthService {
	authService := &authService{
		users: make(map[string]string),
	}
	return authService
}

func (a *authService) Register(username, password string) error {

	if username == "" || password == "" {
		return errors.New("username and password cannot be empty")
	}

	a.mu.Lock()
	defer a.mu.Unlock()


	if _, ok := a.users[username]; 
	ok {
		return errors.New("username already exist")
	}


	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}


	a.users[username] = string(hashedPassword)
	return nil
}
 

func (a *authService) Login(username, password string) (string, error) {

	if username == "" || password == "" {
		return "", errors.New("username and password cannot be empty")
	}

	a.mu.RLock()
	defer a.mu.RUnlock()


	hashedPassword, ok := a.users[username]
	if !ok {
		return "", errors.New("this user does not exist")
	}


	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return "", errors.New("invalid password")
	}

	
	
	token := "jwt_token_for_" + username
	return token, nil
}