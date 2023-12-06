var SEARCH

var INDEX

async function Fetch(){

    SEARCH = await axios.get('search.json')

    INDEX = await axios.get('index.json')


}



function Search(){

    var query_line = $("#seantywork-search-query").val()

    var query_split = query_line.split(" ")

    var search_result = []

    var search_result_html = ''

    for(let i =0; i < query_split.length; i++){


        var el = query_split[i]

        
        for (const [search_key, search_value] of Object.entries(SEARCH)){

            var path_id = ""

            var title_id = ""

            if(search_key.includes(el)){

                path_id = INDEX[search_value]["address"]

                title_id = INDEX[search_value]["title"]

                if(search_result.includes(path_id)){

                    continue

                }else{

                    search_result.push(path_id)

                    search_result_html += `<li><a href="${path_id}">` + title_id + `</a></li>`

                }


            }


        }

    }

    $("#seantywork-search-result").html(search_result_html)

    
}


Fetch()

$("#seantywork-search-query").on("change",Search)