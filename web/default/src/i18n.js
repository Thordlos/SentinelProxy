import i18n from 'i18next';
import {initReactI18next} from 'react-i18next';
import zhTranslation from './locales/zh/translation.json';

i18n
  .use(initReactI18next)
  .init({
    lng: 'zh',
    fallbackLng: 'zh',
    debug: process.env.NODE_ENV === 'development',

    interpolation: {
      escapeValue: false,
    },

    resources: {
      zh: {
        translation: zhTranslation
      }
    }
  });

export default i18n;
