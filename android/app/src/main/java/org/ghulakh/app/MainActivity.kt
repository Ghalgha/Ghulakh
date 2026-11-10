package org.ghulakh.app

import android.app.Activity
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        root.addView(TextView(this).apply { text = "ГӀулакх"; textSize = 28f })
        root.addView(TextView(this).apply { text = "Исследовательская сборка · 0.1.0"; textSize = 14f })
        root.addView(TextView(this).apply {
            text = "Транспорт ещё не подключён. Эта сборка не маршрутизирует трафик."
            textSize = 16f
            setPadding(0, 32, 0, 0)
        })
        setContentView(root)
    }
}
