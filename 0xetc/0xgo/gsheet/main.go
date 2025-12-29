package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"

	gshcore "feebdaed.xyz/git/linuxyz.git/0xetc/0xgo/gsheet/core"
)

func main() {

	ctx := context.Background()

	gsh_conf, err := gshcore.GetGsheetConfig()

	if err != nil {

		fmt.Println(err.Error())

		return

	}

	cred_path := gsh_conf.CRED_PATH

	cred_b, err := os.ReadFile(cred_path)

	if err != nil {

		fmt.Println(err.Error())

		return
	}

	client_config, err := google.ConfigFromJSON(cred_b, "https://www.googleapis.com/auth/spreadsheets.readonly")

	if err != nil {

		fmt.Println(err.Error())

		return
	}

	client, err := gshcore.GetGsheetClient(client_config)

	if err != nil {

		fmt.Println(err.Error())

		return

	}

	srv, err := sheets.NewService(ctx, option.WithHTTPClient(client))

	if err != nil {

		fmt.Println(err.Error())

		return

	}

	sheet_id := gsh_conf.SHEET_ID

	sheets_len := len(gsh_conf.SHEETS)

	for i := 0; i < sheets_len; i++ {

		target_sheet := gsh_conf.SHEETS[i]

		resp, err := srv.Spreadsheets.Values.Get(sheet_id, target_sheet).Do()

		if err != nil {

			fmt.Printf("failed to get values from: %s: %s\n", target_sheet, err.Error())

			return

		}

		if len(resp.Values) == 0 {

			fmt.Printf("no data found for: %s\n", target_sheet)

		} else {

			for _, row := range resp.Values {

				col_len := len(row)

				for j := 0; j < col_len; j++ {

					fmt.Printf("%s ", row[j])

				}

				fmt.Printf("\n")

			}
		}

	}

}
