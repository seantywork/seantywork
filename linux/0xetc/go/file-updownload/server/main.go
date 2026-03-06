package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

func BinaryUpload(c *gin.Context) {

	file, _ := c.FormFile("file")

	rawMediaType := file.Header.Get("Content-Type")

	log.Printf("content type: %s\n", rawMediaType)

	f_name := file.Filename

	this_video_path := "./data/" + f_name

	err := c.SaveUploadedFile(file, this_video_path)

	if err != nil {

		c.String(http.StatusBadRequest, "failed")

		return
	}

	c.String(http.StatusOK, "success")

}

func BinaryDownload(c *gin.Context) {

	binName := c.Param("binName")

	this_video_path := "./data/" + binName

	//c.Header("Content-Type", "video/mp4")

	c.File(this_video_path)

}

func setRoutes(e *gin.Engine) {

	e.POST("/upload", BinaryUpload)

	e.GET("/download/:binName", BinaryDownload)

}

func main() {

	server := gin.Default()

	store := sessions.NewCookieStore([]byte("FILEUPDOWN"))

	server.Use(sessions.Sessions("FILEUPDOWN", store))

	setRoutes(server)

	server.Run("0.0.0.0:8080")

}
