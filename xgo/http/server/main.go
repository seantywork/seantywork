package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

type CommJSON struct {
	Data string `json:"data"`
}

func handlePostHello(c *gin.Context) {

	req := CommJSON{}
	resp := CommJSON{}

	if err := c.BindJSON(&req); err != nil {

		log.Printf("failed to bind json: %s\n", err.Error())

		c.JSON(http.StatusBadRequest, resp)

		return
	}

	resp.Data = req.Data

	c.JSON(http.StatusOK, resp)

}

func createServer() *gin.Engine {

	genserver := gin.Default()

	store := sessions.NewCookieStore([]byte("SOLIAGAIN"))

	genserver.Use(sessions.Sessions("SOLIAGAIN", store))

	//	genserver.LoadHTMLGlob("view/**/*")

	//	genserver.Static("/public", "./public")

	genserver.POST("/hello", handlePostHello)

	return genserver

}

func main() {

	e := createServer()

	e.RunTLS("0.0.0.0:8888", "certs/server.pem", "certs/server.key")

}
