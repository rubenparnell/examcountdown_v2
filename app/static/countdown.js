export function updateCountdown(element) {
    const rows = document.querySelectorAll(element);
    rows.forEach(row => {
        const examDateTime = row.getAttribute('data-exam-datetime');
        const countdownElement = row.querySelector('.countdown');
        const examDate = new Date(examDateTime.replace(/-/g, "/"));
        const now = new Date();
        const timeDifference = examDate - now;

        if (timeDifference > 0) {
            const days = Math.floor(timeDifference / (1000 * 60 * 60 * 24));
            const hours = Math.floor((timeDifference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((timeDifference % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((timeDifference % (1000 * 60)) / 1000);

            countdownElement.textContent = `${days}d ${hours}h ${minutes}m ${seconds}s`;
        } else {
            countdownElement.textContent = "Exam Started/ Ended";
        }
    });
}