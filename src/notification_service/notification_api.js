// Node.js notification API entry point
import express from 'express';
import dotenv from 'dotenv';
import brevo from '@getbrevo/brevo';
import cors from 'cors';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ✅ Authentification Brevo
const defaultClient = brevo.ApiClient.instance;
defaultClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY2;

const emailApi = new brevo.TransactionalEmailsApi();

/**
 * Génère le HTML stylisé du rapport critique
 */
const generateCriticalAlertEmail = (report) => {
    const {
        generatedAt,
        periodStart,
        periodEnd,
        severitySummary,
        typeSummary,
        criticalEvents,
    } = report;

    const severityRows = Object.entries(severitySummary || {})
        .map(
            ([level, count]) =>
                `<tr><td style="padding: 4px 10px;">${level}</td><td style="padding: 4px 10px;">${count}</td></tr>`
        )
        .join('');

    const typeRows = Object.entries(typeSummary || {})
        .map(
            ([type, count]) =>
                `<tr><td style="padding: 4px 10px;">${type}</td><td style="padding: 4px 10px;">${count}</td></tr>`
        )
        .join('');

    const eventDetails = (criticalEvents || [])
        .map(
            (event) => `
        <tr>
            <td style="padding: 4px 10px;">${event.timestamp}</td>
            <td style="padding: 4px 10px;">${event.severity}</td>
            <td style="padding: 4px 10px;">${event.type}</td>
            <td style="padding: 4px 10px;">${event.path}</td>
            <td style="padding: 4px 10px;">${event.description}</td>
        </tr>
    `
        )
        .join('');

    return `
        <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #fef2f2;
                        color: #111;
                        padding: 20px;
                    }
                    h2 {
                        color: #b91c1c;
                    }
                    table {
                        border-collapse: collapse;
                        width: 100%;
                        margin-top: 10px;
                        background-color: #fff;
                        border: 1px solid #ddd;
                    }
                    th, td {
                        border: 1px solid #ddd;
                        padding: 8px;
                        font-size: 14px;
                    }
                    th {
                        background-color: #fca5a5;
                    }
                    .footer {
                        font-size: 12px;
                        margin-top: 20px;
                        color: #555;
                    }
                </style>
            </head>
            <body>
                <h2>🚨 ALERTE IDS CRITIQUE DÉTECTÉE</h2>
                <p><strong>Date de génération:</strong> ${generatedAt}</p>
                <p><strong>Période couverte:</strong> Du ${periodStart} au ${periodEnd}</p>

                <h3>📊 Résumé par gravité</h3>
                <table>
                    <tr><th>Gravité</th><th>Occurrences</th></tr>
                    ${severityRows}
                </table>

                <h3>🗂️ Résumé par type d'événement</h3>
                <table>
                    <tr><th>Type</th><th>Occurrences</th></tr>
                    ${typeRows}
                </table>

                <h3>🔍 Détails des événements CRITIQUES</h3>
                <table>
                    <tr>
                        <th>Horodatage</th>
                        <th>Gravité</th>
                        <th>Type</th>
                        <th>Chemin</th>
                        <th>Description</th>
                    </tr>
                    ${eventDetails}
                </table>

                <div class="footer">
                    <p>Merci de traiter cette alerte en priorité. Toute inaction pourrait mettre en péril la sécurité du système.</p>
                    <p>📧 Émis par: ${process.env.USER_NAME}</p>
                </div>
            </body>
        </html>
    `;
};

/**
 * Envoie l’email via Brevo
 */
const sendCriticalAlertEmail = async (report) => {
    const htmlContent = generateCriticalAlertEmail(report);

    try {
        await emailApi.sendTransacEmail({
            sender: {
                name: process.env.USER_NAME,
                email: process.env.USER_EMAIL,
            },
            to: [{ email: process.env.RECIPIENT_EMAIL }],
            subject: '🚨 ALERTE CRITIQUE - IDS',
            htmlContent,
        });

        return true;
    } catch (error) {
        console.error("Erreur d'envoi d'email :", error);
        return false;
    }
};

/**
 * Route POST pour recevoir le rapport d'alerte
 */
app.post('/ids/alert', async (req, res) => {
    console.log('okk')
    const report = req.body;

    if (!report || !report.generatedAt || !report.criticalEvents) {
        return res
            .status(400)
            .json({ message: 'Rapport invalide ou incomplet.' });
    }

    const success = await sendCriticalAlertEmail(report);

    if (success) {
        res.status(200).json({ message: 'Alerte envoyée avec succès.' });
    } else {
        res.status(500).json({
            message: "Erreur lors de l'envoi de l'alerte.",
        });
    }
});

app.listen(PORT, () => {
    console.log(`🟢 IDS Mail Server running on port ${PORT}`);
});

