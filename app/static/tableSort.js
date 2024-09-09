function convertDateToUnixTime(dateString) {
	// Split the date string into its components
	const [day, month, year, hour, minute] = dateString.split(/[/ :]/).map(Number);
  
	// Create a Date object with the extracted components
	const date = new Date(year, month - 1, day, hour, minute);
  
	// Get the Unix timestamp in milliseconds (epoch time in milliseconds)
	const unixTimeInMilliseconds = date.getTime();
  
	// Convert milliseconds to seconds (divide by 1000)
	const unixTimeInSeconds = unixTimeInMilliseconds / 1000;
  
	return unixTimeInSeconds;
  }
  
function parseTimeStringToMinutes(timeString) {
    const match = timeString.match(/^(\d+)h? (\d+)m?$/);
    if (match) {
        return parseInt(match[1]) * 60 + parseInt(match[2]);
    } else if (timeString.endsWith('m')) {
        return parseInt(timeString.slice(0, -1));
    } else {
        return parseInt(timeString) * 60;
    }
}

 /**
 * Sorts a HTML table.
 *
 * @param {HTMLTableElement} table The table to sort
 * @param {number} column The index of the column to sort
 * @param {string} url The url of the page
 * @param {boolean} asc Determines if the sorting will be in ascending
 */
function sortTableByColumn(table, column, column_index, asc = true) {
	const dirModifier = asc ? 1 : -1;
	const tBody = table.tBodies[0];
	const rows = Array.from(tBody.querySelectorAll("tr"));

	if (column == "duration") {
		sortedRows = rows.sort((a, b) => {
			const aColText = a.querySelector(`td:nth-child(${column_index + 1 })`).textContent.trim();
			const bColText = b.querySelector(`td:nth-child(${column_index + 1 })`).textContent.trim();

			// Parse time strings into minutes
			const aMinutes = parseTimeStringToMinutes(aColText);
			const bMinutes = parseTimeStringToMinutes(bColText);
		
			return aMinutes > bMinutes ? (1 * dirModifier) : (-1 * dirModifier);
		});
	} else if (column == "date") {
		sortedRows = rows.sort((a, b) => {
			const aColText = a.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim();
			const bColText = b.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim();

			aUnixTime = convertDateToUnixTime(aColText)
			bUnixTime = convertDateToUnixTime(bColText)
			
			return aUnixTime > bUnixTime ? (1 * dirModifier) : (-1 * dirModifier);
		})
	} else if (column  == "number") {
		sortedRows = rows.sort((a, b) => {
			const aColText = parseInt(a.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim());
			const bColText = parseInt(b.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim());
			
			return aColText > bColText ? (1 * dirModifier) : (-1 * dirModifier);
		})
	} else { //other columns
		sortedRows = rows.sort((a, b) => {
			const aColText = a.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim();
			const bColText = b.querySelector(`td:nth-child(${ column_index + 1 })`).textContent.trim();
			
			return aColText > bColText ? (1 * dirModifier) : (-1 * dirModifier);
		})
	}

	// Remove all existing TRs from the table
	while (tBody.firstChild) {
		tBody.removeChild(tBody.firstChild);
	}

	// Re-add the newly sorted rows
	tBody.append(...sortedRows);

	// Remember how the column is currently sorted
	table.querySelectorAll("th").forEach(th => th.classList.remove("th-sort-asc", "th-sort-desc"));
	table.querySelector(`th:nth-child(${column_index + 1})`).classList.toggle("th-sort-asc", asc);
	table.querySelector(`th:nth-child(${column_index + 1})`).classList.toggle("th-sort-desc", !asc);
}

document.querySelectorAll(".table-sortable th").forEach(headerCell => {
	if (!headerCell.classList.contains("no-sort")) { // Check for "no-sort" class
		headerCell.addEventListener("click", () => {
			const tableElement = headerCell.parentElement.parentElement.parentElement;
			const column_type = headerCell.getAttribute('data-column');
			const currentIsAscending = headerCell.classList.contains("th-sort-asc");
			const column_index = Array.prototype.indexOf.call(headerCell.parentElement.children, headerCell);

			sortTableByColumn(tableElement, column_type, column_index, !currentIsAscending);
		});
	}
});