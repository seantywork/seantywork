# seantywork

crap compilation of my interests including linux stuff

## intro

- For previous articles published, see [Medium.com](https://medium.com/@seantywork)
- For publicly available source code, see [GitHub.com](https://github.com/seantywork)

## contents
<script>
    (async function() {
        const response = await fetch('https://api.github.com/repos/seantywork/seantywork/contents/');
        const data = await response.json();
        let htmlString = '<ul>';
        
        for (let file of data) {
            htmlString += `<li><a href="${file.path}">${file.name}</a></li>`;
        }

        htmlString += '</ul>';
        document.getElementsByTagName('body')[0].innerHTML = htmlString;
    })()
</script>
