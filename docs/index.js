var INDEX
async function FetchAndSetUpIndex(){
    var index_dat = await axios.get("index.json")
    INDEX = index_dat.data

    var index_html = ''

    for(let i=0;i<INDEX.length;i++){

        var index_obj = INDEX[i]

        var id = index_obj["id"]

        var title = index_obj["title"]

        index_html += `<p><a href="${id}">${title}</a></p>`

    }
 
    $("#seantywork-index").html(index_html)
}
function Search(){
    var query_line = $("#seantywork-index-query").val()
    var query_split = query_line.split(" ")
    var search_result = []
    var search_result_html = ''
    for(let i =0; i < query_split.length; i++){

        var el = query_split[i]


        el = el.toLowerCase()

        if(el == ""){
            continue
        }
        for (const [seq, index_obj] of Object.entries(INDEX)){
            var id = index_obj["id"]
            var title = index_obj["title"]
            var index = index_obj["index"]
            if(index.includes(el)){
                if(search_result.includes(id)){
                    continue
                }else{
                    search_result.push(id)
                    search_result_html += `<li><a href="${id}">` + title + `</a></li>`
                }
            }
        }
    }
    $("#seantywork-search-result").html(search_result_html)
    
}
FetchAndSetUpIndex()
$("#seantywork-index-query").on("input",Search)