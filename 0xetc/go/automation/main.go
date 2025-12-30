package main

import (
	"fmt"
	"strconv"

	"github.com/go-vgo/robotgo"
	"github.com/vcaesar/imgo"
)

func Wheel() {

	robotgo.MouseSleep = 100

	robotgo.ScrollDir(10, "up")
	robotgo.ScrollDir(20, "right")

	robotgo.Scroll(0, -10)
	robotgo.Scroll(100, 0)

	robotgo.MilliSleep(100)
	robotgo.ScrollSmooth(-10, 6)
	// robotgo.ScrollRelative(10, -100)

	robotgo.Move(10, 20)
	robotgo.MoveRelative(0, -10)
	robotgo.DragSmooth(10, 10)

	robotgo.Click("wheelRight")
	robotgo.Click("left", true)
	robotgo.MoveSmooth(100, 200, 1.0, 10.0)

	robotgo.Toggle("left")
	robotgo.Toggle("left", "up")

}

func Keyboard() {

	robotgo.TypeStr("Hello World")
	robotgo.TypeStr("だんしゃり", 0, 1)
	// robotgo.TypeStr("テストする")

	robotgo.TypeStr("Hi, Seattle space needle, Golden gate bridge, One world trade center.")
	robotgo.TypeStr("Hi galaxy, hi stars, hi MT.Rainier, hi sea. こんにちは世界.")
	robotgo.Sleep(1)

	// ustr := uint32(robotgo.CharCodeAt("Test", 0))
	// robotgo.UnicodeType(ustr)

	robotgo.KeySleep = 100
	robotgo.KeyTap("enter")
	// robotgo.TypeStr("en")
	robotgo.KeyTap("i", "alt", "cmd")

	arr := []string{"alt", "cmd"}
	robotgo.KeyTap("i", arr)

	robotgo.MilliSleep(100)
	robotgo.KeyToggle("a")
	robotgo.KeyToggle("a", "up")

	robotgo.WriteAll("Test")
	text, err := robotgo.ReadAll()
	if err == nil {
		fmt.Println(text)
	}

}

func Screenshot() {
	x, y := robotgo.Location()
	fmt.Println("pos: ", x, y)

	color := robotgo.GetPixelColor(100, 200)
	fmt.Println("color---- ", color)

	sx, sy := robotgo.GetScreenSize()
	fmt.Println("get screen size: ", sx, sy)

	bit := robotgo.CaptureScreen(10, 10, 30, 30)
	defer robotgo.FreeBitmap(bit)

	img := robotgo.ToImage(bit)
	imgo.Save("test.png", img)

	num := robotgo.DisplaysNum()
	for i := 0; i < num; i++ {
		robotgo.DisplayID = i
		img1, _ := robotgo.CaptureImg()
		path1 := "save_" + strconv.Itoa(i)
		robotgo.Save(img1, path1+".png")
		robotgo.SaveJpeg(img1, path1+".jpeg", 50)

		img2, _ := robotgo.CaptureImg(10, 10, 20, 20)
		robotgo.Save(img2, "test_"+strconv.Itoa(i)+".png")
	}
}

func main() {

	//Wheel()

	Keyboard()

	//Screenshot()
}
