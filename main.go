package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	jwt "github.com/dgrijalva/jwt-go"
)

type AWSEvent struct {
	Type               string `json:"type"`
	AuthorizationToken string `json:"authorizationToken"`
	MethodArn          string `json:"methodArn"`
}

type AWSPolicy struct {
	Version   string
	Statement []AWSStatement
}

type AWSStatement struct {
	Action   string
	Effect   string
	Resource string
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func main() {
	lambda.Start(authenticateLambda)

	// Use once https://github.com/apex/up/issues/726 is resolved
	addr := ":" + os.Getenv("PORT")
	http.HandleFunc("/", authenticate)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func getToken(e AWSEvent) string {
	log.Println("Event is:", e)

	authHeaderParts := strings.Split(e.AuthorizationToken, " ")
	token := authHeaderParts[1]
	return token
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func getPolicyDocument(effect, resource string) AWSPolicy {
	s := AWSStatement{Action: "execute-api:Invoke", Effect: effect, Resource: resource}
	p := AWSPolicy{Version: "2012-10-17", Statement: []AWSStatement{s}}
	return p
}

func checkToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify Alg
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		aud := os.Getenv("AUTH0_AUDIENCE")
		checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
		if !checkAud {
			return token, errors.New("Invalid audience.")
		}
		// Verify 'iss' claim
		iss := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, errors.New("Invalid issuer.")
		}

		cert, err := getPemCert(token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))

		return result, nil
	})

	return token, err
}

func authenticateLambda(event AWSEvent) (*AWSPolicy, error) {
	tokenString := getToken(event)
	token, err := checkToken(tokenString)

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		p := getPolicyDocument("allow", event.MethodArn)
		return &p, nil
	}

	return nil, err
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	var event AWSEvent

	b, _ := ioutil.ReadAll(r.Body)

	log.Println("Request is:", string(b))

	if err := json.Unmarshal(b, event); err != nil {
		fmt.Fprintln(w, err)
	}

	tokenString := getToken(event)
	token, err := checkToken(tokenString)

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		p := getPolicyDocument("allow", event.MethodArn)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	} else {
		fmt.Fprintln(w, err)
	}
}
