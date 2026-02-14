document.addEventListener('DOMContentLoaded', function() {
    const calendarEl = document.getElementById('calendar');

    if (!calendarEl) return;

    // These variables are expected to exist in the global scope
    const colours = window.CALENDAR_COLOURS || [];
    const events = window.CALENDAR_EVENTS || [];

    const subjectColours = {};
    let colourIndex = 0;

    // Assign colors dynamically
    events.forEach(event => {
        const subj = event.extendedProps.subject;
        if (!subjectColours[subj]) {
            subjectColours[subj] = colours[colourIndex % colours.length];
            colourIndex++;
        }
        event.backgroundColor = subjectColours[subj];
    });

    // Determine first event date
    let firstEventDate = null;
    if (events.length > 0) {
        firstEventDate = new Date(events[0].start);
        for (let i = 1; i < events.length; i++) {
            const d = new Date(events[i].start);
            if (d < firstEventDate) firstEventDate = d;
        }
    }

    // Get today (without time)
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const initialDate = firstEventDate && firstEventDate > today ? firstEventDate : today;

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        themeSystem: 'bootstrap5',
        initialDate: initialDate,
        headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek'
        },
        fixedWeekCount: false,
        dayMaxEventRows: false,
        height: 'auto',
        expandRows: true,
        events: events,
        eventTimeFormat: false,
        eventClick: function(info) {
            const modal = new bootstrap.Modal(document.getElementById('examModal'));
            const props = info.event.extendedProps;

            document.getElementById('modalDate').textContent =
                info.event.start.toLocaleDateString();
            document.getElementById('modalTime').textContent = props.time;
            document.getElementById('modalSubject').textContent = props.subject;

            let titleText = props.title;
            if (props.tier) titleText += " (" + props.tier + ")";
            document.getElementById('modalTitle').textContent = titleText;

            document.getElementById('modalDuration').textContent = props.duration;
            document.getElementById('modalBoard').textContent = props.board;

            modal.show();
        }
    });

    calendar.render();
});
