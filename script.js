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
            coll[i].classList.toggle("active");
            var content = coll[i].nextElementSibling;
            content.style.maxHeight = null;
        }
        expanded = false;
    }
    else {
        for (i = 0; i < coll.length; i++) {
            coll[i].classList.toggle("active");
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

// Use bubble sort to sort the results
function sortTable(col_index, table_id) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
    table = document.getElementById(table_id);
    switching = true;
    // Set the sorting direction to ascending
    dir = "asc"; 
    // Make a loop that will continue until no switching has been done
    while (switching) {
        // Start by saying: no switching is done
        switching = false;
        rows = table.rows;
        // Loop through all table rows (except the first, which contains table headers)
        for (i = 1; i < (rows.length - 1); i++) {
            // Start by saying there should be no switching
            shouldSwitch = false;
            // Get the two elements you want to compare, one from current row and one from the next
            x = rows[i].getElementsByTagName("TD")[col_index];
            y = rows[i + 1].getElementsByTagName("TD")[col_index];
            // Check if the two rows should switch place, based on the direction, asc or desc.
            // If they are float (or int) they should be sorted as numbers, otherwise as strings.
            if (dir == "asc") {
                if ((isNaN(parseFloat(x.innerHTML)) || isNaN(parseFloat(y.innerHTML))) ? 
                    (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) : 
                    (parseFloat(x.innerHTML) > parseFloat(y.innerHTML))) {
                    // If so, mark as a switch and break the loop
                    shouldSwitch = true;
                    break;
                }
            } 
            else if (dir == "desc") {
                if ((isNaN(parseFloat(x.innerHTML)) || isNaN(parseFloat(y.innerHTML))) ? 
                    (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) : 
                    (parseFloat(x.innerHTML) < parseFloat(y.innerHTML))) {
                    // If so, mark as a switch and break the loop
                    shouldSwitch = true;
                    break;
                }
            }
        }
        if (shouldSwitch) {
            // If a switch has been marked, make the switch and mark that a switch has been done
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            // Each time a switch is done, increase this count by 1
            switchcount ++; 
        } 
        else {
            // If no switching has been done AND the direction is "asc", set the direction to "desc" and run the while loop again.
            if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
}

function fetchReport() {
    var newDate = document.getElementById("datepicker").value;
    var url = window.location.href;
    var newUrl = url.replace(/\d+-\d+-\d+/, newDate);
    var request;
    try {
        if(window.XMLHttpRequest)
            request = new XMLHttpRequest();
        else
            request = new ActiveXObject("Microsoft.XMLHTTP");
        request.open('GET', newUrl, true);
        request.onreadystatechange = function(){
            if (request.readyState === 4){
                if (request.status === 404 || request.status === 403) {  
                    alert("Report for this date does not exist.");
                }
                else
                window.location.assign(newUrl);
            }
        };
        request.send();
    }
    catch(err) {
        alert(err);
    }
}