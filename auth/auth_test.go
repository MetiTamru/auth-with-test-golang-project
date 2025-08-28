package auth

import (

	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/bcrypt"
)


var _ = Describe("AuthService", func() {
	var auth AuthService

	BeforeEach(func() {
		auth = NewAuthService()
	})

	Describe("Register", func() {
		Context("successful registration", func() {
			It("should register a user without error", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("failed registration", func() {
			It("should return and error for empty password", func() {
				err := auth.Register("meti", "")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("cannot be empty"))
			})
		})

		Context("failed registration", func() {
			It("should return and error for empty user name", func() {
				err := auth.Register("", "meti1234")
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("cannot be empty"))
			})
		})

		Context("failed registration due to duplication", func() {
			It("should return and error for duplicated user name", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				err = auth.Register("meti", "meti2244")
				Expect(err).To(HaveOccurred())

				Expect(err.Error()).To(ContainSubstring("already exist"))
			})
		})

		Context("successful registration", func() {

			It("should register a user with special character in their name and password", func() {

				err := auth.Register("meti@gmail.com", "meti%&*()")
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("safe password hashing", func() {

			It("hash the password of a new registered user correctly not plain text", func() {


        auth := NewAuthService().(*authService)  
        password := "meti1234"

				err := auth.Register("meti",password)
				Expect(err).ToNot(HaveOccurred())

				auth.mu.RLock()
				storedHash := auth.users["meti"]
				auth.mu.RUnlock()

				Expect(storedHash).ToNot(Equal(password))

				err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))

        Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("safe concurrency",func ()  {
			It("should hadle concurret registration safely",func ()  {
			  var wg sync.WaitGroup
				attempt := 100
				result := make(chan error, attempt)
				
				for i := 0; i < attempt; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						err := auth.Register("meti","meti1234")
						result <- err
					}()
				}
				wg.Wait()
				close(result)

				successCount := 0

				for err := range result {
					if err == nil {
						successCount++
					}
				}
				Expect(successCount).To(Equal(1))
			})
		})

	})


	//login tests

		Describe("Login", func() {

		Context("successful login", func() {
			It("should login a user without error", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("meti","meti1234")

				Expect(logErr).ToNot(HaveOccurred())
				Expect(token).ToNot(BeEmpty())
			})
		})

		Context("failed login", func() {
			It("should return and error for empty password", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("meti","")

				Expect(logErr).To(HaveOccurred())
				Expect(token).To(BeEmpty())
				Expect(logErr.Error()).To(ContainSubstring("cannot be empty"))
			})
		})

		Context("failed login", func() {
			It("should return and error for empty user name", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("","meti1234")

				Expect(logErr).To(HaveOccurred())
				Expect(token).To(BeEmpty())
				Expect(logErr.Error()).To(ContainSubstring("cannot be empty"))
			})
		})

		Context("failed login", func() {
			It("should return and error for wrong password", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("meti","meti12345")

				Expect(logErr).To(HaveOccurred())
				Expect(token).To(BeEmpty())
				Expect(logErr.Error()).To(ContainSubstring("invalid password"))
			})
		})

		Context("failed login", func() {
			It("should return and error for non existing user", func() {
				err := auth.Register("meti", "meti1234")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("meti-tamiru","meti1234")

				Expect(logErr).To(HaveOccurred())
				Expect(token).To(BeEmpty())
				Expect(logErr.Error()).To(ContainSubstring("user does not exist"))
			})
		})

		Context("succesful login", func() {
			It("should login a user with special character user name and password", func() {

				err := auth.Register("meti@yahoo.com", "meti(&^%$")
				Expect(err).ToNot(HaveOccurred())

				token, logErr := auth.Login("meti@yahoo.com","meti(&^%$")

				Expect(logErr).ToNot(HaveOccurred())
				Expect(token).ToNot(BeEmpty())
			})
		})

		Context("safe concurrency",func ()  {
			It("should hadle concurret login safely",func ()  {
			  
				var wg sync.WaitGroup

				err := auth.Register("meti","meti1234")
				Expect(err).ToNot(HaveOccurred())

				attempt := 100
				result := make(chan error, attempt)
				

				for i := 0; i < attempt; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
           _, err := auth.Login("meti", "meti1234")
						result <- err
					}()
				}
				wg.Wait()
				close(result)

				successCount := 0

				for err := range result {
					if err == nil {
						successCount++
					}
				}
				Expect(successCount).To(Equal(100))
			})
		})

	})
})
