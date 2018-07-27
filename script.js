var coll = document.getElementsByClassName("collapsible");
var expanded = false;
var i;

for (i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", toggle);
}

function toggle() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.maxHeight){
        content.style.maxHeight = null;
    } else {
        content.style.maxHeight = content.scrollHeight + "px";
    } 
}

function toggleAll() {
    var coll = document.getElementsByClassName("collapsible");
    var i;
    if(expanded) {
        for (i = 0; i < coll.length; i++) {
            coll[i].classList.toggle("active", false);
            var content = coll[i].nextElementSibling;
            content.style.maxHeight = null;
        }
        expanded = false;
    }
    else {
        for (i = 0; i < coll.length; i++) {
            coll[i].classList.toggle("active", true);
            var content = coll[i].nextElementSibling;
            content.style.maxHeight = content.scrollHeight + "px";
        }
        expanded = true;
    }

    var btn = document.getElementById("toggleBtn")
    if(btn.innerText == "Expand All")
        btn.innerText = "Collapse All";
    else
        btn.innerText = "Expand All";
}
