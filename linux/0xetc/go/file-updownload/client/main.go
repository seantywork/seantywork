package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

func Upload(client *http.Client, url string, values map[string]io.Reader) (err error) {

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for key, r := range values {
		var fw io.Writer
		if x, ok := r.(io.Closer); ok {
			defer x.Close()
		}

		if x, ok := r.(*os.File); ok {
			if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
				return
			}
		} else {
			// Add other fields
			if fw, err = w.CreateFormField(key); err != nil {
				return
			}
		}
		if _, err = io.Copy(fw, r); err != nil {
			return err
		}

	}

	w.Close()

	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := client.Do(req)
	if err != nil {
		return
	}

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	}
	return
}

func Download(filepath string, url string) (err error) {

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	v, err := os.Open("./data/test.mp4")

	if err != nil {
		log.Printf("failed to read data: %v\n", err)
		os.Exit(-1)
	}

	values := map[string]io.Reader{
		"file":  v,
		"other": strings.NewReader("hello world!"),
	}

	client := &http.Client{}

	err = Upload(client, "http://localhost:8080/upload", values)

	if err != nil {

		log.Printf("failed to upload file: %v\n", err)

		os.Exit(-1)
	}

	err = Download("./data/return.mp4", "http://localhost:8080/download/test.mp4")

	if err != nil {
		log.Printf("failed to download file: %v\n", err)

		os.Exit(-1)
	}

	os.Exit(0)

}
