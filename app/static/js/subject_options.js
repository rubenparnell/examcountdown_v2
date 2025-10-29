document.addEventListener("DOMContentLoaded", () => {
  const subjectDropdown = document.getElementById("subjectDropdown");
  const baseSubjectInput = document.getElementById("base_subject");
  const boardSelect = document.getElementById("board");
  const specificDrop = document.getElementById("specific_subject_drop");
  const specificSelect = document.getElementById("specific_subject");
  const tierDrop = document.getElementById("tier_drop");
  const tierSelect = document.getElementById("tier");
  const addButton = document.getElementById("addButton");
  const searchInput = document.getElementById("search_subject");
  const subjectMenu = subjectDropdown.nextElementSibling; // the <ul> element

  // Build category structure: [{header, subjects: [li, li, ...]}]
  const categories = [];
  let currentCategory = null;

  Array.from(subjectMenu.children).forEach(li => {
    const header = li.querySelector(".dropdown-header");
    const subjectItem = li.querySelector(".subject-item");

    if (header) {
      currentCategory = { header: header, subjects: [] };
      categories.push(currentCategory);
    } else if (subjectItem && currentCategory) {
      currentCategory.subjects.push(li);

      // Subject click
      subjectItem.addEventListener("click", async e => {
        e.preventDefault();
        const subject = e.target.dataset.value;
        subjectDropdown.textContent = subject;
        baseSubjectInput.value = subject;

        // Fetch boards
        const res = await fetch(`/user/api/boards/${subject}`);
        const data = await res.json();

        boardSelect.innerHTML = `<option disabled selected>Select a Board</option>`;
        data.boards.forEach(b => {
          const opt = document.createElement("option");
          opt.value = b;
          opt.textContent = b;
          boardSelect.appendChild(opt);
        });
        boardSelect.disabled = false;
        specificDrop.style.display = "none";
        tierDrop.style.display = "none";
        addButton.disabled = true;

        // ✅ Auto-select if only one board
        if (data.boards.length === 1) {
          boardSelect.value = data.boards[0];
          boardSelect.dispatchEvent(new Event("change"));
        }
      });
    }
  });

  // Search subjects and show/hide category headers
  searchInput.addEventListener("input", () => {
    const value = searchInput.value.toLowerCase();

    categories.forEach(cat => {
      let anyVisible = false;

      cat.subjects.forEach(li => {
        const item = li.querySelector(".subject-item");
        const match = item.dataset.value.toLowerCase().includes(value);
        li.style.display = match ? "block" : "none";
        if (match) anyVisible = true;
      });

      cat.header.style.display = anyVisible ? "block" : "none";
    });
  });

  // Board select
  boardSelect.addEventListener("change", async () => {
    const subject = baseSubjectInput.value;
    const board = boardSelect.value;
    const res = await fetch(`/user/api/specific_subjects/${subject}/${board}`);
    const data = await res.json();

    specificSelect.innerHTML = `<option disabled selected>Select Your Specific Subject</option>`;
    data.specific_subjects.forEach(s => {
      const opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s;
      specificSelect.appendChild(opt);
    });

    specificSelect.disabled = false;
    specificDrop.style.display = "block";
    tierDrop.style.display = "none";
    addButton.disabled = true;

    // ✅ Auto-select if only one specific subject
    if (data.specific_subjects.length === 1) {
      specificSelect.value = data.specific_subjects[0];
      specificSelect.dispatchEvent(new Event("change"));
    }
  });

  // Specific subject select
  specificSelect.addEventListener("change", async () => {
    const subject = baseSubjectInput.value;
    const board = boardSelect.value;
    const specific = specificSelect.value;
    const res = await fetch(`/user/api/tiers/${subject}/${board}/${specific}`);
    const data = await res.json();

    if (data.tiers.length > 0) {
      tierSelect.innerHTML = `<option disabled selected>Select a Tier</option>`;
      data.tiers.forEach(t => {
        const opt = document.createElement("option");
        opt.value = t;
        opt.textContent = t;
        tierSelect.appendChild(opt);
      });
      tierSelect.disabled = false;
      tierDrop.style.display = "block";
    } else {
      tierDrop.style.display = "none";
      tierSelect.disabled = true;
    }

    addButton.disabled = false;
  });
});
